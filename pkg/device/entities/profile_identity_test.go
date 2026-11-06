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

// TestDeviceProfile_IdentityFields_RoundTrip checks that the EK serial,
// MAC address and assignment fields survive both JSON and YAML encoding.
func TestDeviceProfile_IdentityFields_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	profile := &DeviceProfile{
		ID:         30,
		Name:       "identity-profile",
		EKSerial:   "SERIAL-001",
		MACAddress: "aa:bb:cc:dd:ee:ff",
		Assigned:   true,
		AssignedAt: now,
	}

	codecs := map[string]struct {
		marshal   func(any) ([]byte, error)
		unmarshal func([]byte, any) error
	}{
		"json": {json.Marshal, json.Unmarshal},
		"yaml": {yaml.Marshal, yaml.Unmarshal},
	}

	for name, codec := range codecs {
		t.Run(name, func(t *testing.T) {
			data, err := codec.marshal(profile)
			require.NoError(t, err)

			var decoded DeviceProfile
			require.NoError(t, codec.unmarshal(data, &decoded))

			assert.Equal(t, "SERIAL-001", decoded.EKSerial)
			assert.Equal(t, "aa:bb:cc:dd:ee:ff", decoded.MACAddress)
			assert.True(t, decoded.Assigned)
			assert.Equal(t, now.Unix(), decoded.AssignedAt.Unix())
		})
	}
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
