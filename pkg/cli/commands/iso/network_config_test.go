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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

func testNetworkConfig() *testenv.NetworkConfig {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
	return &testenv.NetworkConfig{
		BridgeName:    "tp-br",
		ServerTapName: "tp-server",
		ClientTapName: "tp-client",
		GatewayIP:     net.ParseIP("10.0.0.1"),
		ServerIP:      net.ParseIP("10.0.0.2"),
		ClientIP:      net.ParseIP("10.0.0.3"),
		Subnet:        subnet,
		Domain:        "example.local",
	}
}

// =============================================================================
// ApplyNetworkConfig
// =============================================================================

func TestApplyNetworkConfig_Server(t *testing.T) {
	inputYAML := []byte("debug: false\nnetwork:\n  dns:\n    nameservers: []\n")
	netCfg := testNetworkConfig()

	result, err := ApplyNetworkConfig(inputYAML, netCfg, platformTypeServer, true)
	require.NoError(t, err)
	require.NotEmpty(t, result)

	assert.Contains(t, string(result), "debug: true")
	assert.Contains(t, string(result), "10.0.0.2")
}

func TestApplyNetworkConfig_Client(t *testing.T) {
	inputYAML := []byte("debug: false\nnetwork: {}\n")
	netCfg := testNetworkConfig()

	result, err := ApplyNetworkConfig(inputYAML, netCfg, platformTypeClient, false)
	require.NoError(t, err)
	require.NotEmpty(t, result)

	assert.Contains(t, string(result), "10.0.0.3")
	assert.Contains(t, string(result), "example.local")
}

func TestApplyNetworkConfig_DHCP(t *testing.T) {
	inputYAML := []byte("debug: false\n")

	result, err := ApplyNetworkConfig(inputYAML, nil, platformTypeDHCP, false)
	require.NoError(t, err)
	require.NotEmpty(t, result)

	assert.Contains(t, string(result), "dhcp")
}

func TestApplyNetworkConfig_InvalidYAML(t *testing.T) {
	_, err := ApplyNetworkConfig([]byte("{{not valid yaml"), nil, platformTypeDHCP, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}

func TestApplyNetworkConfig_UnsupportedType(t *testing.T) {
	inputYAML := []byte("debug: false\n")
	_, err := ApplyNetworkConfig(inputYAML, nil, "invalid-type", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported platform type")
}

// =============================================================================
// buildNetworkOverride
// =============================================================================

func TestBuildNetworkOverride_Server_NilConfig(t *testing.T) {
	_, err := buildNetworkOverride(nil, platformTypeServer)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestBuildNetworkOverride_Client_NilConfig(t *testing.T) {
	_, err := buildNetworkOverride(nil, platformTypeClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestBuildNetworkOverride_DHCP(t *testing.T) {
	result, err := buildNetworkOverride(nil, platformTypeDHCP)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result["dns"])
	assert.NotNil(t, result["interfaces"])
}

func TestBuildNetworkOverride_UnsupportedType(t *testing.T) {
	_, err := buildNetworkOverride(nil, "bad-type")
	require.Error(t, err)
}

func TestBuildNetworkOverride_Server_ValidConfig(t *testing.T) {
	netCfg := testNetworkConfig()
	result, err := buildNetworkOverride(netCfg, platformTypeServer)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestBuildNetworkOverride_Client_ValidConfig(t *testing.T) {
	netCfg := testNetworkConfig()
	result, err := buildNetworkOverride(netCfg, platformTypeClient)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// =============================================================================
// buildServerNetwork
// =============================================================================

func TestBuildServerNetwork(t *testing.T) {
	netCfg := testNetworkConfig()
	result := buildServerNetwork(netCfg)

	assert.NotNil(t, result["dns"])
	assert.NotNil(t, result["interfaces"])
	assert.Equal(t, true, result["wait-online"])
	assert.Equal(t, 30, result["wait-timeout"])

	interfaces := result["interfaces"].([]map[string]interface{})
	require.Len(t, interfaces, 1)
	assert.Equal(t, "eth0", interfaces[0]["name"])
	assert.Equal(t, "static", interfaces[0]["type"])
	assert.Equal(t, "10.0.0.2", interfaces[0]["ipv4-address"])
	assert.Equal(t, "10.0.0.1", interfaces[0]["ipv4-gateway"])
}

// =============================================================================
// buildClientNetwork
// =============================================================================

func TestBuildClientNetwork(t *testing.T) {
	netCfg := testNetworkConfig()
	result := buildClientNetwork(netCfg)

	dns := result["dns"].(map[string]interface{})
	assert.Contains(t, dns["upstream-dns"], "10.0.0.2#9053")

	searchDomains := dns["search-domains"].([]string)
	assert.Contains(t, searchDomains, "example.local")

	interfaces := result["interfaces"].([]map[string]interface{})
	require.Len(t, interfaces, 1)
	assert.Equal(t, "10.0.0.3", interfaces[0]["ipv4-address"])
}

// =============================================================================
// buildDHCPNetwork
// =============================================================================

func TestBuildDHCPNetwork(t *testing.T) {
	result := buildDHCPNetwork()

	dns := result["dns"].(map[string]interface{})
	nameservers := dns["nameservers"].([]string)
	assert.Contains(t, nameservers, "8.8.8.8")

	interfaces := result["interfaces"].([]map[string]interface{})
	require.Len(t, interfaces, 1)
	assert.Equal(t, "dhcp", interfaces[0]["type"])
}
