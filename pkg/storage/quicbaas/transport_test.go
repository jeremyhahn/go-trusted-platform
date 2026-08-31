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

package quicbaas

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransport_String(t *testing.T) {
	tests := []struct {
		transport Transport
		expected  string
	}{
		{TransportEmbedded, "embedded"},
		{TransportUnix, "unix"},
		{TransportGRPC, "grpc"},
		{TransportREST, "rest"},
		{TransportQUIC, "quic"},
		{Transport(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.transport.String())
		})
	}
}

func TestParseTransport_ValidValues(t *testing.T) {
	tests := []struct {
		input    string
		expected Transport
	}{
		{"embedded", TransportEmbedded},
		{"EMBEDDED", TransportEmbedded},
		{"Embedded", TransportEmbedded},
		{"", TransportEmbedded}, // Empty defaults to embedded
		{"unix", TransportUnix},
		{"UNIX", TransportUnix},
		{"Unix", TransportUnix},
		{"grpc", TransportGRPC},
		{"GRPC", TransportGRPC},
		{"gRPC", TransportGRPC},
		{"rest", TransportREST},
		{"REST", TransportREST},
		{"Rest", TransportREST},
		{"quic", TransportQUIC},
		{"QUIC", TransportQUIC},
		{"Quic", TransportQUIC},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseTransport(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseTransport_InvalidValue(t *testing.T) {
	invalidValues := []string{
		"invalid",
		"websocket",
		"tcp",
		"http",
		"https",
	}

	for _, input := range invalidValues {
		t.Run(input, func(t *testing.T) {
			result, err := ParseTransport(input)

			// Should still return embedded as default
			assert.Equal(t, TransportEmbedded, result)

			// But should also return an error
			require.Error(t, err)
			var transportErr ErrInvalidTransport
			assert.ErrorAs(t, err, &transportErr)
			assert.Equal(t, input, transportErr.Value)
		})
	}
}

func TestParseTransport_WhitespaceHandling(t *testing.T) {
	tests := []struct {
		input    string
		expected Transport
	}{
		{"  embedded  ", TransportEmbedded},
		{"  unix  ", TransportUnix},
		{"\tgrpc\t", TransportGRPC},
		{"\nrest\n", TransportREST},
		{" quic ", TransportQUIC},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseTransport(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_IsEmbedded(t *testing.T) {
	tests := []struct {
		transport Transport
		expected  bool
	}{
		{TransportEmbedded, true},
		{TransportUnix, false},
		{TransportGRPC, false},
		{TransportREST, false},
		{TransportQUIC, false},
	}

	for _, tt := range tests {
		t.Run(tt.transport.String(), func(t *testing.T) {
			cfg := &Config{Transport: tt.transport}
			assert.Equal(t, tt.expected, cfg.IsEmbedded())
		})
	}
}

func TestConfig_IsRemote(t *testing.T) {
	tests := []struct {
		transport Transport
		expected  bool
	}{
		{TransportEmbedded, false},
		{TransportUnix, true},
		{TransportGRPC, true},
		{TransportREST, true},
		{TransportQUIC, true},
	}

	for _, tt := range tests {
		t.Run(tt.transport.String(), func(t *testing.T) {
			cfg := &Config{Transport: tt.transport}
			assert.Equal(t, tt.expected, cfg.IsRemote())
		})
	}
}

func TestRemoteConfig(t *testing.T) {
	tests := []struct {
		name      string
		transport Transport
		address   string
	}{
		{"grpc", TransportGRPC, "localhost:10443"},
		{"rest", TransportREST, "http://localhost:8443"},
		{"quic", TransportQUIC, "localhost:9444"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := RemoteConfig(tt.transport, tt.address)

			assert.Equal(t, tt.transport, cfg.Transport)
			assert.Equal(t, tt.transport.String(), cfg.TransportStr)
			assert.Equal(t, tt.address, cfg.Address)
			assert.Equal(t, 30*time.Second, cfg.RequestTimeout)
			assert.Equal(t, ConsistencyLinearizable, cfg.ConsistencyLevel)
		})
	}
}

func TestUnixSocketConfig(t *testing.T) {
	socketPath := "/var/run/quicbaas.sock"
	cfg := UnixSocketConfig(socketPath)

	assert.Equal(t, TransportUnix, cfg.Transport)
	assert.Equal(t, "unix", cfg.TransportStr)
	assert.Equal(t, socketPath, cfg.UnixSocket)
	assert.Equal(t, 30*time.Second, cfg.RequestTimeout)
	assert.Equal(t, ConsistencyLinearizable, cfg.ConsistencyLevel)
}

func TestConfig_Validate_UnixTransport_MissingSocket(t *testing.T) {
	cfg := &Config{
		Transport:      TransportUnix,
		UnixSocket:     "", // Missing
		RequestTimeout: 30 * time.Second,
	}

	err := cfg.Validate()
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
	assert.Equal(t, "UnixSocket", invalidCfgErr.Field)
}

func TestConfig_Validate_UnixTransport_Valid(t *testing.T) {
	cfg := &Config{
		Transport:      TransportUnix,
		UnixSocket:     "/var/run/quicbaas.sock",
		RequestTimeout: 30 * time.Second,
	}

	err := cfg.Validate()
	require.NoError(t, err)
}

func TestConfig_Validate_GRPCTransport_MissingAddress(t *testing.T) {
	cfg := &Config{
		Transport:      TransportGRPC,
		Address:        "", // Missing
		RequestTimeout: 30 * time.Second,
	}

	err := cfg.Validate()
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
	assert.Equal(t, "Address", invalidCfgErr.Field)
}

func TestConfig_Validate_GRPCTransport_Valid(t *testing.T) {
	cfg := &Config{
		Transport:      TransportGRPC,
		Address:        "localhost:10443",
		RequestTimeout: 30 * time.Second,
	}

	err := cfg.Validate()
	require.NoError(t, err)
}

func TestConfig_Validate_RESTTransport_MissingAddress(t *testing.T) {
	cfg := &Config{
		Transport:      TransportREST,
		Address:        "", // Missing
		RequestTimeout: 30 * time.Second,
	}

	err := cfg.Validate()
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
	assert.Equal(t, "Address", invalidCfgErr.Field)
}

func TestConfig_Validate_RESTTransport_Valid(t *testing.T) {
	cfg := &Config{
		Transport:      TransportREST,
		Address:        "http://localhost:8443",
		RequestTimeout: 30 * time.Second,
	}

	err := cfg.Validate()
	require.NoError(t, err)
}

func TestConfig_Validate_QUICTransport_MissingAddress(t *testing.T) {
	cfg := &Config{
		Transport:      TransportQUIC,
		Address:        "", // Missing
		RequestTimeout: 30 * time.Second,
	}

	err := cfg.Validate()
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
	assert.Equal(t, "Address", invalidCfgErr.Field)
}

func TestConfig_Validate_QUICTransport_Valid(t *testing.T) {
	cfg := &Config{
		Transport:      TransportQUIC,
		Address:        "localhost:9444",
		RequestTimeout: 30 * time.Second,
	}

	err := cfg.Validate()
	require.NoError(t, err)
}

func TestConfig_Validate_InvalidTransport(t *testing.T) {
	cfg := &Config{
		Transport:      Transport(99), // Invalid
		RequestTimeout: 30 * time.Second,
	}

	err := cfg.Validate()
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
	assert.Equal(t, "Transport", invalidCfgErr.Field)
}

func TestDefaultConfig_IncludesTransport(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, TransportEmbedded, cfg.Transport)
	assert.Equal(t, "embedded", cfg.TransportStr)
	assert.True(t, cfg.IsEmbedded())
	assert.False(t, cfg.IsRemote())
}

func TestTestConfig_IncludesTransport(t *testing.T) {
	cfg := TestConfig(t)

	assert.Equal(t, TransportEmbedded, cfg.Transport)
	assert.Equal(t, "embedded", cfg.TransportStr)
	assert.True(t, cfg.IsEmbedded())
}

func TestMemoryTestConfig_IncludesTransport(t *testing.T) {
	cfg := MemoryTestConfig(t)

	assert.Equal(t, TransportEmbedded, cfg.Transport)
	assert.Equal(t, "embedded", cfg.TransportStr)
	assert.True(t, cfg.IsEmbedded())
}

func TestFileTestConfig_IncludesTransport(t *testing.T) {
	cfg := FileTestConfig(t)

	assert.Equal(t, TransportEmbedded, cfg.Transport)
	assert.Equal(t, "embedded", cfg.TransportStr)
	assert.True(t, cfg.IsEmbedded())
}

func TestRaftTestConfig_IncludesTransport(t *testing.T) {
	cfg := RaftTestConfig(t)

	assert.Equal(t, TransportEmbedded, cfg.Transport)
	assert.Equal(t, "embedded", cfg.TransportStr)
	assert.True(t, cfg.IsEmbedded())
}

// Tests for ParseTransportFromConfig method
func TestConfig_ParseTransportFromConfig_ValidValues(t *testing.T) {
	tests := []struct {
		name         string
		transportStr string
		expected     Transport
	}{
		{"embedded", "embedded", TransportEmbedded},
		{"unix", "unix", TransportUnix},
		{"grpc", "grpc", TransportGRPC},
		{"rest", "rest", TransportREST},
		{"quic", "quic", TransportQUIC},
		{"empty_defaults_to_embedded", "", TransportEmbedded},
		{"case_insensitive", "GRPC", TransportGRPC},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				TransportStr:   tt.transportStr,
				RequestTimeout: 30 * time.Second,
			}

			err := cfg.ParseTransportFromConfig()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, cfg.Transport)

			// TransportStr should be normalized for empty input
			if tt.transportStr == "" {
				assert.Equal(t, "embedded", cfg.TransportStr)
			}
		})
	}
}

func TestConfig_ParseTransportFromConfig_InvalidValue(t *testing.T) {
	cfg := &Config{
		TransportStr:   "invalid",
		RequestTimeout: 30 * time.Second,
	}

	err := cfg.ParseTransportFromConfig()
	require.Error(t, err)

	var transportErr ErrInvalidTransport
	assert.ErrorAs(t, err, &transportErr)
	assert.Equal(t, "invalid", transportErr.Value)
}

func TestConfig_SetTransport(t *testing.T) {
	tests := []struct {
		transport      Transport
		expectedStr    string
		expectedRemote bool
	}{
		{TransportEmbedded, "embedded", false},
		{TransportUnix, "unix", true},
		{TransportGRPC, "grpc", true},
		{TransportREST, "rest", true},
		{TransportQUIC, "quic", true},
	}

	for _, tt := range tests {
		t.Run(tt.expectedStr, func(t *testing.T) {
			cfg := &Config{}
			cfg.SetTransport(tt.transport)

			assert.Equal(t, tt.transport, cfg.Transport)
			assert.Equal(t, tt.expectedStr, cfg.TransportStr)
			assert.Equal(t, tt.expectedRemote, cfg.IsRemote())
		})
	}
}

func TestConfig_Validate_ParsesTransportStr(t *testing.T) {
	// Test that Validate() calls ParseTransportFromConfig when needed
	cfg := &Config{
		TransportStr:   "grpc",
		Address:        "localhost:10443",
		RequestTimeout: 30 * time.Second,
	}

	// Transport is TransportEmbedded (0) by default
	assert.Equal(t, TransportEmbedded, cfg.Transport)

	// Validate should parse the TransportStr and set Transport
	err := cfg.Validate()
	require.NoError(t, err)

	// Now Transport should be set correctly
	assert.Equal(t, TransportGRPC, cfg.Transport)
}

func TestConfig_Validate_SkipsParsingWhenTransportStrMatchesDefault(t *testing.T) {
	// Test that embedded transport with "embedded" TransportStr doesn't trigger parsing
	cfg := &Config{
		TransportStr:      "embedded",
		Transport:         TransportEmbedded,
		StorageBackend:    "pebble",
		DataDir:           "/tmp/test",
		WALDir:            "/tmp/test/wal",
		RequestTimeout:    30 * time.Second,
		SPIFFETrustDomain: "example.internal",
	}

	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, TransportEmbedded, cfg.Transport)
}

// Simulate YAML config loading scenario
func TestConfig_YAMLConfigLoadingScenario(t *testing.T) {
	// Simulate a config loaded from YAML where only TransportStr is set
	// (mapstructure sets TransportStr from YAML "transport" field)
	cfg := &Config{
		TransportStr:   "unix", // Loaded from YAML: transport: unix
		Transport:      0,      // Enum not set by mapstructure
		UnixSocket:     "/var/run/quicbaas.sock",
		RequestTimeout: 30 * time.Second,
	}

	// Parse the transport string to set the enum
	err := cfg.ParseTransportFromConfig()
	require.NoError(t, err)

	// Now the Transport enum should be set
	assert.Equal(t, TransportUnix, cfg.Transport)
	assert.True(t, cfg.IsRemote())
	assert.False(t, cfg.IsEmbedded())

	// Validate should pass
	err = cfg.Validate()
	require.NoError(t, err)
}

func TestConfig_YAMLConfigLoadingScenario_gRPC(t *testing.T) {
	// Simulate a config loaded from YAML for gRPC transport
	cfg := &Config{
		TransportStr:   "grpc", // Loaded from YAML: transport: grpc
		Transport:      0,      // Enum not set by mapstructure
		Address:        "localhost:10443",
		RequestTimeout: 30 * time.Second,
	}

	// Parse and validate
	err := cfg.ParseTransportFromConfig()
	require.NoError(t, err)
	assert.Equal(t, TransportGRPC, cfg.Transport)

	err = cfg.Validate()
	require.NoError(t, err)
}

func TestConfig_YAMLConfigLoadingScenario_DefaultEmbedded(t *testing.T) {
	// Simulate a config loaded from YAML with no transport specified
	// (defaults to embedded)
	cfg := &Config{
		TransportStr:      "", // Empty or not specified in YAML
		Transport:         0,  // Default
		StorageBackend:    "pebble",
		DataDir:           "/tmp/test",
		WALDir:            "/tmp/test/wal",
		RequestTimeout:    30 * time.Second,
		SPIFFETrustDomain: "example.internal",
	}

	// Parse and validate
	err := cfg.ParseTransportFromConfig()
	require.NoError(t, err)
	assert.Equal(t, TransportEmbedded, cfg.Transport)
	assert.Equal(t, "embedded", cfg.TransportStr) // Should be normalized

	err = cfg.Validate()
	require.NoError(t, err)
}
