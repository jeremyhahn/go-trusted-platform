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

package dns

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

const yamlData = `
datastore:
  backend: fs
  consistency-level: local
  home: trusted-data/datastore
  read-buffer-size: 50
  serializer: json
public:
  port: 8053
  forwarders:
    - 4.4.4.4
    - 8.8.8.8
  zone:
    description: Public zone for example.com
    name: example.com.
    ttl: 3600
    records:
      soa:
        name: example.com.
        mname: ns1.example.com.
        rname: hostmaster.example.com.
        serial: 1
        refresh: 86400
        retry: 7200
        expire: 86400
        minimum_ttl: 3600
        ttl: 3600
      ns:
        - name: example.com.
          value: ns1.example.com.
          ttl: 3600
        - name: example.com.
          value: ns2.example.com.
          ttl: 3600
        - name: example.com.
          value: ns3.example.com.
          ttl: 3600
      a:
        - name: ns1
          value: ${PUBLIC_IPv4}
          ttl: 3600
        - name: ns2
          value: ${PUBLIC_IPv4}
          ttl: 3600
        - name: ns3
          value: ${PUBLIC_IPv4}
          ttl: 3600
        - name: www
          value: ${PUBLIC_IPv4}
          ttl: 3600
      cname:
        - name: www
          value: example.com.
          ttl: 3600
      mx:
        - name: example.com.
          value: mail.example.com.
          priority: 10
          ttl: 3600
      txt:
        - name: example.com.
          value: v=spf1 include:_spf.google.com ~all
          ttl: 3600
internal:
  port: 9053
  forwarders:
    - 192.168.1.1
    - 192.168.2.1
    - 192.168.3.1
  zone:
    description: Internal zone for example.internal
    name: example.internal.
    ttl: 3600
    internal: true
    records:
      soa:
        name: example.internal.
        mname: ns1.example.internal.
        rname: hostmaster.example.internal.
        serial: 1
        refresh: 86400
        retry: 7200
        expire: 86400
        minimum_ttl: 3600
        ttl: 3600
      ns:
        - name: example.internal.
          value: ns1.example.internal.
          ttl: 3600
        - name: example.internal.
          value: ns2.example.internal.
          ttl: 3600
        - name: example.internal.
          value: ns3.example.internal.
          ttl: 3600
      a:
        - name: ns1
          value: ${LOCAL_IPv4}
          ttl: 3600
        - name: ns2
          value: 192.168.2.1
          ttl: 3600
        - name: ns3
          value: 192.168.3.1
          ttl: 3600
        - name: ${HOSTNAME}
          value: ${LOCAL_IPv4}
          ttl: 3600
      cname:
        - name: www
          value: example.internal.
          ttl: 3600`

func TestParseConfig(t *testing.T) {

	var config Config

	err := yaml.Unmarshal([]byte(yamlData), &config)
	assert.NoError(t, err, "Failed to unmarshal YAML configuration")

	// Public Zone Assertions
	publicZone := config.PublicServer.Zone
	assert.Equal(t, "example.com.", publicZone.Name)
	assert.Equal(t, "Public zone for example.com", publicZone.Description)
	assert.Len(t, publicZone.RecordSet.NSRecords, 3, "NSRecords count mismatch in Public Zone")
	assert.Len(t, publicZone.RecordSet.ARecords, 4, "ARecords count mismatch in Public Zone")
	assert.Len(t, publicZone.RecordSet.CNAMERecords, 1, "CNAMERecords count mismatch in Public Zone")
	assert.Len(t, publicZone.RecordSet.MXRecords, 1, "MXRecords count mismatch in Public Zone")
	assert.Len(t, publicZone.RecordSet.TXTRecords, 1, "TXTRecords count mismatch in Public Zone")

	// Internal Zone Assertions
	internalZone := config.InternalServer.Zone
	assert.Equal(t, "example.internal.", internalZone.Name)
	assert.Equal(t, "Internal zone for example.internal", internalZone.Description)
	assert.True(t, internalZone.Internal, "Internal flag mismatch in Internal Zone")
	assert.Len(t, internalZone.RecordSet.NSRecords, 3, "NSRecords count mismatch in Internal Zone")
	assert.Len(t, internalZone.RecordSet.ARecords, 4, "ARecords count mismatch in Internal Zone")
	assert.Len(t, internalZone.RecordSet.CNAMERecords, 1, "CNAMERecords count mismatch in Internal Zone")
}

func TestConfigSerialization(t *testing.T) {
	// Step 1: Serialize DefaultConfig to YAML
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	err := encoder.Encode(DefaultConfig)
	assert.NoError(t, err, "Failed to serialize DefaultConfig to YAML")

	// Step 2: Deserialize back into a Config object
	var deserializedConfig Config
	decoder := yaml.NewDecoder(&buf)
	err = decoder.Decode(&deserializedConfig)
	assert.NoError(t, err, "Failed to deserialize YAML into Config")

	// Step 3: Assert QuicBaaS configurations match (compare individual fields to handle nil vs empty slice)
	assert.Equal(t, DefaultConfig.QuicBaaS.StorageBackend, deserializedConfig.QuicBaaS.StorageBackend, "QuicBaaS.StorageBackend mismatch")
	assert.Equal(t, DefaultConfig.QuicBaaS.DataDir, deserializedConfig.QuicBaaS.DataDir, "QuicBaaS.DataDir mismatch")
	assert.Equal(t, DefaultConfig.QuicBaaS.WALDir, deserializedConfig.QuicBaaS.WALDir, "QuicBaaS.WALDir mismatch")
	assert.Equal(t, DefaultConfig.QuicBaaS.NodeID, deserializedConfig.QuicBaaS.NodeID, "QuicBaaS.NodeID mismatch")
	assert.Equal(t, DefaultConfig.QuicBaaS.CacheSize, deserializedConfig.QuicBaaS.CacheSize, "QuicBaaS.CacheSize mismatch")
	assert.Equal(t, DefaultConfig.QuicBaaS.LogLevel, deserializedConfig.QuicBaaS.LogLevel, "QuicBaaS.LogLevel mismatch")
	assert.Equal(t, DefaultConfig.QuicBaaS.ConsistencyLevel, deserializedConfig.QuicBaaS.ConsistencyLevel, "QuicBaaS.ConsistencyLevel mismatch")

	// Step 4: Assert PublicServer configurations match
	publicZone := deserializedConfig.PublicServer.Zone
	assert.Equal(t, DefaultConfig.PublicServer.Zone.Name, publicZone.Name, "PublicServer.Zone.Name mismatch")
	assert.Equal(t, DefaultConfig.PublicServer.Zone.Description, publicZone.Description, "PublicServer.Zone.Description mismatch")
	assert.Len(t, publicZone.RecordSet.NSRecords, 3, "PublicServer.Zone NSRecords count mismatch")
	assert.Len(t, publicZone.RecordSet.ARecords, 4, "PublicServer.Zone ARecords count mismatch")
	assert.Len(t, publicZone.RecordSet.CNAMERecords, 0, "PublicServer.Zone CNAMERecords count mismatch")
	assert.Len(t, publicZone.RecordSet.MXRecords, 1, "PublicServer.Zone MXRecords count mismatch")
	assert.Len(t, publicZone.RecordSet.TXTRecords, 1, "PublicServer.Zone TXTRecords count mismatch")

	// Assert PublicServer individual records
	assert.Equal(t, DefaultConfig.PublicServer.Zone.RecordSet.NSRecords, publicZone.RecordSet.NSRecords, "PublicServer.Zone NSRecords mismatch")
	assert.Equal(t, DefaultConfig.PublicServer.Zone.RecordSet.ARecords, publicZone.RecordSet.ARecords, "PublicServer.Zone ARecords mismatch")
	// CNAMERecords: empty slice vs nil are equivalent for this test
	assert.Empty(t, publicZone.RecordSet.CNAMERecords, "PublicServer.Zone CNAMERecords should be empty")
	assert.Equal(t, DefaultConfig.PublicServer.Zone.RecordSet.MXRecords, publicZone.RecordSet.MXRecords, "PublicServer.Zone MXRecords mismatch")
	assert.Equal(t, DefaultConfig.PublicServer.Zone.RecordSet.TXTRecords, publicZone.RecordSet.TXTRecords, "PublicServer.Zone TXTRecords mismatch")

	// Step 5: Assert InternalServer configurations match
	internalZone := deserializedConfig.InternalServer.Zone
	assert.Equal(t, DefaultConfig.InternalServer.Zone.Name, internalZone.Name, "InternalServer.Zone.Name mismatch")
	assert.Equal(t, DefaultConfig.InternalServer.Zone.Description, internalZone.Description, "InternalServer.Zone.Description mismatch")
	assert.True(t, internalZone.Internal, "InternalServer.Zone.Internal flag mismatch")
	assert.Len(t, internalZone.RecordSet.NSRecords, 3, "InternalServer.Zone NSRecords count mismatch")
	assert.Len(t, internalZone.RecordSet.ARecords, 4, "InternalServer.Zone ARecords count mismatch")
	assert.Len(t, internalZone.RecordSet.CNAMERecords, 1, "InternalServer.Zone CNAMERecords count mismatch")

	// Assert InternalServer individual records
	assert.Equal(t, DefaultConfig.InternalServer.Zone.RecordSet.NSRecords, internalZone.RecordSet.NSRecords, "InternalServer.Zone NSRecords mismatch")
	assert.Equal(t, DefaultConfig.InternalServer.Zone.RecordSet.ARecords, internalZone.RecordSet.ARecords, "InternalServer.Zone ARecords mismatch")
	assert.Equal(t, DefaultConfig.InternalServer.Zone.RecordSet.CNAMERecords, internalZone.RecordSet.CNAMERecords, "InternalServer.Zone CNAMERecords mismatch")
}

func TestConfig_HasServer(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected bool
	}{
		{
			name:     "both servers configured",
			config:   Config{PublicServer: &PublicServer{Port: 8053}, InternalServer: &InternalServer{Port: 9053}},
			expected: true,
		},
		{
			name:     "public server only",
			config:   Config{PublicServer: &PublicServer{Port: 8053}},
			expected: true,
		},
		{
			name:     "internal server only",
			config:   Config{InternalServer: &InternalServer{Port: 9053}},
			expected: true,
		},
		{
			name:     "resolver only",
			config:   Config{Resolver: &ResolverConfig{Servers: []ResolverServer{{Address: "127.0.0.1", Port: 8053}}}},
			expected: false,
		},
		{
			name:     "empty config",
			config:   Config{},
			expected: false,
		},
		{
			name:     "default config has servers",
			config:   DefaultConfig,
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.config.HasServer())
		})
	}
}

func TestConfig_HasServer_ResolverOnly_NoCoreDNS(t *testing.T) {
	// Verify that a client config with only resolver settings
	// does not indicate it should run a DNS server.
	config := Config{
		Resolver: &ResolverConfig{
			Servers:  []ResolverServer{{Address: "10.0.0.1", Port: 53}},
			Fallback: []string{"1.1.1.1:53", "8.8.8.8:53"},
		},
	}
	assert.False(t, config.HasServer(),
		"resolver-only config must not indicate a server is configured")
	assert.NotNil(t, config.Resolver,
		"resolver config should remain accessible for DANE lookups")
}
