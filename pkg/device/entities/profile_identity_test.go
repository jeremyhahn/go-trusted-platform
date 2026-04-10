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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// testConfig is a simple struct used to exercise the Config field
// without importing pkg/app (which would cause an import cycle).
type testConfig struct {
	Domain   string `json:"domain" yaml:"domain"`
	Hostname string `json:"hostname" yaml:"hostname"`
}

func TestDeviceProfile_Config(t *testing.T) {
	cfg := &testConfig{
		Domain:   "test.example.com",
		Hostname: "node-01",
	}

	profile := &DeviceProfile{
		ID:     1,
		Name:   "config-profile",
		Config: cfg,
	}

	assert.NotNil(t, profile.Config)

	got, ok := profile.Config.(*testConfig)
	require.True(t, ok)
	assert.Equal(t, "test.example.com", got.Domain)
	assert.Equal(t, "node-01", got.Hostname)
}

func TestDeviceProfile_Config_Nil(t *testing.T) {
	profile := &DeviceProfile{
		ID:   2,
		Name: "no-config-profile",
	}

	assert.Nil(t, profile.Config)
}

func TestDeviceProfile_Config_JSONRoundTrip(t *testing.T) {
	cfg := map[string]string{
		"domain":   "json.example.com",
		"hostname": "json-node",
	}

	profile := &DeviceProfile{
		ID:     3,
		Name:   "json-config-profile",
		Config: cfg,
	}

	data, err := json.Marshal(profile)
	require.NoError(t, err)

	var decoded DeviceProfile
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.NotNil(t, decoded.Config)
	// JSON round-trip deserializes any to map[string]interface{}
	m, ok := decoded.Config.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "json.example.com", m["domain"])
	assert.Equal(t, "json-node", m["hostname"])
}

func TestDeviceProfile_EKSerial(t *testing.T) {
	profile := &DeviceProfile{
		ID:       10,
		Name:     "ek-profile",
		EKSerial: "ABC123DEF456",
	}

	assert.Equal(t, "ABC123DEF456", profile.EKSerial)
}

func TestDeviceProfile_EKSerial_Empty(t *testing.T) {
	profile := &DeviceProfile{
		ID:   11,
		Name: "no-ek-profile",
	}

	assert.Equal(t, "", profile.EKSerial)
}

func TestDeviceProfile_EKSerial_JSONRoundTrip(t *testing.T) {
	profile := &DeviceProfile{
		ID:       12,
		Name:     "ek-json-profile",
		EKSerial: "SERIAL-001",
	}

	data, err := json.Marshal(profile)
	require.NoError(t, err)

	var decoded DeviceProfile
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "SERIAL-001", decoded.EKSerial)
}

func TestDeviceProfile_EKSerial_YAMLRoundTrip(t *testing.T) {
	profile := &DeviceProfile{
		ID:       13,
		Name:     "ek-yaml-profile",
		EKSerial: "SERIAL-002",
	}

	data, err := yaml.Marshal(profile)
	require.NoError(t, err)

	var decoded DeviceProfile
	err = yaml.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "SERIAL-002", decoded.EKSerial)
}

func TestDeviceProfile_MACAddress(t *testing.T) {
	profile := &DeviceProfile{
		ID:         20,
		Name:       "mac-profile",
		MACAddress: "52:54:00:ab:cd:ef",
	}

	assert.Equal(t, "52:54:00:ab:cd:ef", profile.MACAddress)
}

func TestDeviceProfile_MACAddress_Empty(t *testing.T) {
	profile := &DeviceProfile{
		ID:   21,
		Name: "no-mac-profile",
	}

	assert.Equal(t, "", profile.MACAddress)
}

func TestDeviceProfile_MACAddress_JSONRoundTrip(t *testing.T) {
	profile := &DeviceProfile{
		ID:         22,
		Name:       "mac-json-profile",
		MACAddress: "aa:bb:cc:dd:ee:ff",
	}

	data, err := json.Marshal(profile)
	require.NoError(t, err)

	var decoded DeviceProfile
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "aa:bb:cc:dd:ee:ff", decoded.MACAddress)
}

func TestDeviceProfile_MACAddress_YAMLRoundTrip(t *testing.T) {
	profile := &DeviceProfile{
		ID:         23,
		Name:       "mac-yaml-profile",
		MACAddress: "11:22:33:44:55:66",
	}

	data, err := yaml.Marshal(profile)
	require.NoError(t, err)

	var decoded DeviceProfile
	err = yaml.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "11:22:33:44:55:66", decoded.MACAddress)
}

func TestDeviceProfile_Assigned(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	profile := &DeviceProfile{
		ID:         30,
		Name:       "assigned-profile",
		EKSerial:   "EK-ASSIGNED-001",
		MACAddress: "52:54:00:01:02:03",
		Assigned:   true,
		AssignedAt: now,
	}

	assert.True(t, profile.Assigned)
	assert.Equal(t, now, profile.AssignedAt)
}

func TestDeviceProfile_Assigned_Default(t *testing.T) {
	profile := &DeviceProfile{
		ID:   31,
		Name: "unassigned-profile",
	}

	assert.False(t, profile.Assigned)
	assert.True(t, profile.AssignedAt.IsZero())
}

func TestDeviceProfile_Assigned_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	profile := &DeviceProfile{
		ID:         32,
		Name:       "assigned-json-profile",
		Assigned:   true,
		AssignedAt: now,
	}

	data, err := json.Marshal(profile)
	require.NoError(t, err)

	var decoded DeviceProfile
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.True(t, decoded.Assigned)
	assert.Equal(t, now.Unix(), decoded.AssignedAt.Unix())
}

func TestDeviceProfile_Assigned_YAMLRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	profile := &DeviceProfile{
		ID:         33,
		Name:       "assigned-yaml-profile",
		Assigned:   true,
		AssignedAt: now,
	}

	data, err := yaml.Marshal(profile)
	require.NoError(t, err)

	var decoded DeviceProfile
	err = yaml.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.True(t, decoded.Assigned)
	assert.Equal(t, now.Unix(), decoded.AssignedAt.Unix())
}

func TestDeviceProfile_AllNewFields(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cfg := &testConfig{
		Domain:   "full.example.com",
		Hostname: "full-node",
	}

	profile := &DeviceProfile{
		ID:         40,
		TenantID:   "tenant-001",
		Name:       "full-profile",
		Model:      "TPM-2000",
		Role:       DeviceRoleServer,
		Config:     cfg,
		EKSerial:   "EK-FULL-001",
		MACAddress: "52:54:00:ff:ee:dd",
		Assigned:   true,
		AssignedAt: now,
	}

	assert.Equal(t, uint64(40), profile.ID)
	assert.Equal(t, "tenant-001", profile.TenantID)
	assert.Equal(t, "EK-FULL-001", profile.EKSerial)
	assert.Equal(t, "52:54:00:ff:ee:dd", profile.MACAddress)
	assert.True(t, profile.Assigned)
	assert.Equal(t, now, profile.AssignedAt)
	assert.NotNil(t, profile.Config)
}

func TestDeviceProfile_AllNewFields_OmittedWhenEmpty_JSON(t *testing.T) {
	profile := &DeviceProfile{
		ID:   41,
		Name: "minimal-profile",
	}

	data, err := json.Marshal(profile)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.NotContains(t, jsonStr, `"config"`)
	assert.NotContains(t, jsonStr, `"ek_serial"`)
	assert.NotContains(t, jsonStr, `"mac_address"`)
}

func TestDeviceProfile_AllNewFields_OmittedWhenEmpty_YAML(t *testing.T) {
	profile := &DeviceProfile{
		ID:   42,
		Name: "minimal-yaml-profile",
	}

	data, err := yaml.Marshal(profile)
	require.NoError(t, err)

	yamlStr := string(data)
	assert.NotContains(t, yamlStr, "config")
	assert.NotContains(t, yamlStr, "ek-serial")
	assert.NotContains(t, yamlStr, "mac-address")
}
