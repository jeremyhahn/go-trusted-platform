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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

func TestISOBuildConfig_DeviceProfile(t *testing.T) {
	t.Run("Get inline device profile", func(t *testing.T) {
		profile := &entities.DeviceProfile{
			ID:    1,
			Name:  "test-server",
			Model: "TestServer",
			Role:  entities.DeviceRoleServer,
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultEnrollmentNetwork: {
					VLAN:    100,
					Gateway: "10.0.100.1",
					DNS:     []string{"10.0.100.2"},
				},
			},
		}

		config := &ISOBuildConfig{
			DeviceProfile: profile,
		}

		result, err := config.GetDeviceProfile()
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, profile.ID, result.ID)
		assert.Equal(t, profile.Name, result.Name)
		assert.Equal(t, profile.Model, result.Model)
	})

	t.Run("Get device profile from file", func(t *testing.T) {
		tmpDir := t.TempDir()
		profilePath := filepath.Join(tmpDir, "profile.yaml")

		profile := &entities.DeviceProfile{
			ID:    2,
			Name:  "file-server",
			Model: "FileServer",
			Role:  entities.DeviceRoleServer,
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultPostEnrollmentNetwork: {
					VLAN:     200,
					StaticIP: "10.0.200.50/24",
					Gateway:  "10.0.200.1",
					DNS:      []string{"10.0.200.2"},
				},
			},
		}

		err := SaveDeviceProfileToFile(profile, profilePath)
		require.NoError(t, err)

		config := &ISOBuildConfig{
			DeviceProfilePath: profilePath,
		}

		result, err := config.GetDeviceProfile()
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, profile.ID, result.ID)
		assert.Equal(t, profile.Name, result.Name)
		assert.NotNil(t, result.GetPostEnrollmentNetworkConfig())
		assert.Equal(t, uint16(200), result.GetPostEnrollmentNetworkConfig().VLAN)
	})

	t.Run("Get device profile returns nil when not configured", func(t *testing.T) {
		config := &ISOBuildConfig{}

		result, err := config.GetDeviceProfile()
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("Error when profile file does not exist", func(t *testing.T) {
		config := &ISOBuildConfig{
			DeviceProfilePath: "/nonexistent/profile.yaml",
		}

		result, err := config.GetDeviceProfile()
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to load device profile")
	})

	t.Run("Inline profile takes precedence over file path", func(t *testing.T) {
		tmpDir := t.TempDir()
		profilePath := filepath.Join(tmpDir, "profile.yaml")

		fileProfile := &entities.DeviceProfile{
			ID:   1,
			Name: "file-profile",
		}
		err := SaveDeviceProfileToFile(fileProfile, profilePath)
		require.NoError(t, err)

		inlineProfile := &entities.DeviceProfile{
			ID:   2,
			Name: "inline-profile",
		}

		config := &ISOBuildConfig{
			DeviceProfile:     inlineProfile,
			DeviceProfilePath: profilePath,
		}

		result, err := config.GetDeviceProfile()
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, uint64(2), result.ID)
		assert.Equal(t, "inline-profile", result.Name)
	})
}

func TestLoadDeviceProfileFromFile(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Load valid profile", func(t *testing.T) {
		profilePath := filepath.Join(tmpDir, "valid-profile.yaml")

		profile := &entities.DeviceProfile{
			ID:    1,
			Name:  "valid-profile",
			Model: "TestModel",
			Role:  entities.DeviceRoleServer,
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultEnrollmentNetwork: {
					VLAN:    100,
					Gateway: "10.0.100.1",
					DNS:     []string{"10.0.100.2", "10.0.100.3"},
					DHCPPool: &entities.DHCPPoolConfig{
						Network:    "10.0.100.0/24",
						RangeStart: "10.0.100.10",
						RangeEnd:   "10.0.100.250",
						LeaseTime:  3600,
					},
				},
				entities.DefaultPostEnrollmentNetwork: {
					VLAN:     200,
					StaticIP: "10.0.200.50/24",
					Gateway:  "10.0.200.1",
					DNS:      []string{"10.0.200.2"},
				},
				entities.DefaultFailureNetwork: {
					VLAN:    300,
					Gateway: "10.0.300.1",
					DNS:     []string{"10.0.300.2"},
				},
			},
		}

		err := SaveDeviceProfileToFile(profile, profilePath)
		require.NoError(t, err)

		loaded, err := LoadDeviceProfileFromFile(profilePath)
		require.NoError(t, err)
		require.NotNil(t, loaded)

		assert.Equal(t, profile.ID, loaded.ID)
		assert.Equal(t, profile.Name, loaded.Name)
		assert.Equal(t, profile.Model, loaded.Model)
		assert.Equal(t, profile.Role, loaded.Role)

		// Verify provisioning network
		require.NotNil(t, loaded.GetEnrollmentNetworkConfig())
		assert.Equal(t, uint16(100), loaded.GetEnrollmentNetworkConfig().VLAN)
		assert.Equal(t, "10.0.100.1", loaded.GetEnrollmentNetworkConfig().Gateway)
		assert.Len(t, loaded.GetEnrollmentNetworkConfig().DNS, 2)
		require.NotNil(t, loaded.GetEnrollmentNetworkConfig().DHCPPool)
		assert.Equal(t, "10.0.100.0/24", loaded.GetEnrollmentNetworkConfig().DHCPPool.Network)

		// Verify production network
		require.NotNil(t, loaded.GetPostEnrollmentNetworkConfig())
		assert.Equal(t, uint16(200), loaded.GetPostEnrollmentNetworkConfig().VLAN)
		assert.Equal(t, "10.0.200.50/24", loaded.GetPostEnrollmentNetworkConfig().StaticIP)

		// Verify quarantine network
		require.NotNil(t, loaded.GetFailureNetworkConfig())
		assert.Equal(t, uint16(300), loaded.GetFailureNetworkConfig().VLAN)
	})

	t.Run("Load profile with ACLs", func(t *testing.T) {
		profilePath := filepath.Join(tmpDir, "profile-with-acls.yaml")

		profile := &entities.DeviceProfile{
			ID:   2,
			Name: "acl-profile",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultEnrollmentNetwork: {
					VLAN: 100,
					ACLs: []entities.ACLConfig{
						{
							Priority: 100,
							Protocol: "tcp",
							SrcIP:    "0.0.0.0/0",
							DstIP:    "10.0.100.2/32",
							DstPort:  443,
							Action:   "allow",
						},
						{
							Priority: 90,
							Protocol: "udp",
							SrcIP:    "0.0.0.0/0",
							DstIP:    "10.0.100.2/32",
							DstPort:  53,
							Action:   "allow",
						},
					},
				},
			},
		}

		err := SaveDeviceProfileToFile(profile, profilePath)
		require.NoError(t, err)

		loaded, err := LoadDeviceProfileFromFile(profilePath)
		require.NoError(t, err)
		require.NotNil(t, loaded)
		require.NotNil(t, loaded.GetEnrollmentNetworkConfig())
		require.Len(t, loaded.GetEnrollmentNetworkConfig().ACLs, 2)

		assert.Equal(t, 100, loaded.GetEnrollmentNetworkConfig().ACLs[0].Priority)
		assert.Equal(t, "tcp", loaded.GetEnrollmentNetworkConfig().ACLs[0].Protocol)
		assert.Equal(t, uint16(443), loaded.GetEnrollmentNetworkConfig().ACLs[0].DstPort)

		assert.Equal(t, 90, loaded.GetEnrollmentNetworkConfig().ACLs[1].Priority)
		assert.Equal(t, "udp", loaded.GetEnrollmentNetworkConfig().ACLs[1].Protocol)
	})

	t.Run("Error on nonexistent file", func(t *testing.T) {
		loaded, err := LoadDeviceProfileFromFile("/nonexistent/profile.yaml")
		assert.Error(t, err)
		assert.Nil(t, loaded)
		assert.Contains(t, err.Error(), "failed to read device profile file")
	})

	t.Run("Error on invalid YAML", func(t *testing.T) {
		profilePath := filepath.Join(tmpDir, "invalid.yaml")
		err := os.WriteFile(profilePath, []byte("invalid: yaml: content:\n  - bad\n    - indentation"), 0600)
		require.NoError(t, err)

		loaded, err := LoadDeviceProfileFromFile(profilePath)
		assert.Error(t, err)
		assert.Nil(t, loaded)
		assert.Contains(t, err.Error(), "failed to parse device profile YAML")
	})
}

func TestSaveDeviceProfileToFile(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Save simple profile", func(t *testing.T) {
		profilePath := filepath.Join(tmpDir, "save-test.yaml")

		profile := &entities.DeviceProfile{
			ID:    1,
			Name:  "save-test",
			Model: "TestModel",
			Role:  entities.DeviceRoleServer,
		}

		err := SaveDeviceProfileToFile(profile, profilePath)
		require.NoError(t, err)

		// Verify file exists
		assert.FileExists(t, profilePath)

		// Verify file permissions
		info, err := os.Stat(profilePath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

		// Verify content is valid YAML
		data, err := os.ReadFile(profilePath)
		require.NoError(t, err)

		var loaded entities.DeviceProfile
		err = yaml.Unmarshal(data, &loaded)
		require.NoError(t, err)

		assert.Equal(t, profile.ID, loaded.ID)
		assert.Equal(t, profile.Name, loaded.Name)
	})

	t.Run("Save profile with all network phases", func(t *testing.T) {
		profilePath := filepath.Join(tmpDir, "full-profile.yaml")

		profile := &entities.DeviceProfile{
			ID:    2,
			Name:  "full-profile",
			Model: "FullModel",
			Role:  entities.DeviceRoleServer,
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultEnrollmentNetwork: {
					VLAN:    100,
					Gateway: "10.0.100.1",
				},
				entities.DefaultPostEnrollmentNetwork: {
					VLAN:    200,
					Gateway: "10.0.200.1",
				},
				entities.DefaultFailureNetwork: {
					VLAN:    300,
					Gateway: "10.0.300.1",
				},
			},
		}

		err := SaveDeviceProfileToFile(profile, profilePath)
		require.NoError(t, err)

		// Load and verify
		loaded, err := LoadDeviceProfileFromFile(profilePath)
		require.NoError(t, err)
		require.NotNil(t, loaded.GetEnrollmentNetworkConfig())
		require.NotNil(t, loaded.GetPostEnrollmentNetworkConfig())
		require.NotNil(t, loaded.GetFailureNetworkConfig())

		assert.Equal(t, uint16(100), loaded.GetEnrollmentNetworkConfig().VLAN)
		assert.Equal(t, uint16(200), loaded.GetPostEnrollmentNetworkConfig().VLAN)
		assert.Equal(t, uint16(300), loaded.GetFailureNetworkConfig().VLAN)
	})

	t.Run("Error on invalid path", func(t *testing.T) {
		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "error-test",
		}

		err := SaveDeviceProfileToFile(profile, "/nonexistent/directory/profile.yaml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write device profile file")
	})

	t.Run("Overwrite existing file", func(t *testing.T) {
		profilePath := filepath.Join(tmpDir, "overwrite-test.yaml")

		profile1 := &entities.DeviceProfile{
			ID:   1,
			Name: "profile1",
		}
		err := SaveDeviceProfileToFile(profile1, profilePath)
		require.NoError(t, err)

		profile2 := &entities.DeviceProfile{
			ID:   2,
			Name: "profile2",
		}
		err = SaveDeviceProfileToFile(profile2, profilePath)
		require.NoError(t, err)

		// Verify latest profile is saved
		loaded, err := LoadDeviceProfileFromFile(profilePath)
		require.NoError(t, err)
		assert.Equal(t, uint64(2), loaded.ID)
		assert.Equal(t, "profile2", loaded.Name)
	})
}

func TestISOBuildConfigWithDeviceProfileValidation(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Validate config with inline device profile", func(t *testing.T) {
		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "test-profile",
		}

		config := DefaultISOBuildConfig()
		config.DeviceProfile = profile

		err := config.Validate()
		require.NoError(t, err)
	})

	t.Run("Validate config with device profile path", func(t *testing.T) {
		profilePath := filepath.Join(tmpDir, "validate-profile.yaml")
		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "validate-test",
		}
		err := SaveDeviceProfileToFile(profile, profilePath)
		require.NoError(t, err)

		config := DefaultISOBuildConfig()
		config.DeviceProfilePath = profilePath

		err = config.Validate()
		require.NoError(t, err)
	})

	t.Run("Validate config with platform API endpoint", func(t *testing.T) {
		config := DefaultISOBuildConfig()
		config.PlatformAPIEndpoint = "https://platform.example.com/api/v1"

		err := config.Validate()
		require.NoError(t, err)
	})

	t.Run("Config with all device profile options", func(t *testing.T) {
		profilePath := filepath.Join(tmpDir, "all-options.yaml")
		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "all-options",
		}
		err := SaveDeviceProfileToFile(profile, profilePath)
		require.NoError(t, err)

		config := DefaultISOBuildConfig()
		config.DeviceProfile = profile
		config.DeviceProfilePath = profilePath
		config.PlatformAPIEndpoint = "https://platform.example.com/api/v1"

		err = config.Validate()
		require.NoError(t, err)
	})
}

func TestDeviceProfileYAMLSerialization(t *testing.T) {
	t.Run("Marshal and unmarshal profile", func(t *testing.T) {
		profile := &entities.DeviceProfile{
			ID:    12345,
			Name:  "yaml-test",
			Model: "YAMLModel",
			Role:  entities.DeviceRoleServer,
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultEnrollmentNetwork: {
					VLAN:    100,
					Gateway: "10.0.100.1",
					DNS:     []string{"10.0.100.2"},
					DHCPPool: &entities.DHCPPoolConfig{
						Network:    "10.0.100.0/24",
						RangeStart: "10.0.100.10",
						RangeEnd:   "10.0.100.250",
						LeaseTime:  3600,
					},
					ACLs: []entities.ACLConfig{
						{
							Priority: 100,
							Protocol: "tcp",
							SrcIP:    "0.0.0.0/0",
							DstIP:    "10.0.100.2/32",
							DstPort:  443,
							Action:   "allow",
						},
					},
				},
			},
		}

		// Marshal to YAML
		data, err := yaml.Marshal(profile)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Verify YAML contains expected fields
		yamlStr := string(data)
		assert.Contains(t, yamlStr, "id: 12345")
		assert.Contains(t, yamlStr, "name: yaml-test")
		assert.Contains(t, yamlStr, "model: YAMLModel")
		assert.Contains(t, yamlStr, "role: server")
		assert.Contains(t, yamlStr, "vlan: 100")
		assert.Contains(t, yamlStr, "gateway: 10.0.100.1")

		// Unmarshal back
		var unmarshaled entities.DeviceProfile
		err = yaml.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, profile.ID, unmarshaled.ID)
		assert.Equal(t, profile.Name, unmarshaled.Name)
		assert.Equal(t, profile.Model, unmarshaled.Model)
		assert.Equal(t, profile.Role, unmarshaled.Role)
		require.NotNil(t, unmarshaled.GetEnrollmentNetworkConfig())
		assert.Equal(t, uint16(100), unmarshaled.GetEnrollmentNetworkConfig().VLAN)
	})
}
