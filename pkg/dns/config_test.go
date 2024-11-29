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
    description: Public zone for trusted-platform.io
    name: trusted-platform.io.
    ttl: 3600
    records:
      soa:
        name: trusted-platform.io.
        mname: ns1.trusted-platform.io.
        rname: hostmaster.trusted-platform.io.
        serial: 1
        refresh: 86400
        retry: 7200
        expire: 86400
        minimum_ttl: 3600
        ttl: 3600
      ns:
        - name: trusted-platform.io.
          value: ns1.trusted-platform.io.
          ttl: 3600
        - name: trusted-platform.io.
          value: ns2.trusted-platform.io.
          ttl: 3600
        - name: trusted-platform.io.
          value: ns3.trusted-platform.io.
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
          value: trusted-platform.io.
          ttl: 3600
      mx:
        - name: trusted-platform.io.
          value: mail.trusted-platform.io.
          priority: 10
          ttl: 3600
      txt:
        - name: trusted-platform.io.
          value: v=spf1 include:_spf.google.com ~all
          ttl: 3600
internal:
  port: 8054
  forwarders:
    - 192.168.1.1
    - 192.168.2.1
    - 192.168.3.1
  zone:
    description: Internal zone for trusted-platform.internal
    name: trusted-platform.internal.
    ttl: 3600
    internal: true
    records:
      soa:
        name: trusted-platform.internal.
        mname: ns1.trusted-platform.internal.
        rname: hostmaster.trusted-platform.internal.
        serial: 1
        refresh: 86400
        retry: 7200
        expire: 86400
        minimum_ttl: 3600
        ttl: 3600
      ns:
        - name: trusted-platform.internal.
          value: ns1.trusted-platform.internal.
          ttl: 3600
        - name: trusted-platform.internal.
          value: ns2.trusted-platform.internal.
          ttl: 3600
        - name: trusted-platform.internal.
          value: ns3.trusted-platform.internal.
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
          value: trusted-platform.internal.
          ttl: 3600`

func TestParseConfig(t *testing.T) {

	var config Config

	err := yaml.Unmarshal([]byte(yamlData), &config)
	assert.NoError(t, err, "Failed to unmarshal YAML configuration")

	// Public Zone Assertions
	publicZone := config.PublicServer.Zone
	assert.Equal(t, "trusted-platform.io.", publicZone.Name)
	assert.Equal(t, "Public zone for trusted-platform.io", publicZone.Description)
	assert.Len(t, publicZone.RecordSet.NSRecords, 3, "NSRecords count mismatch in Public Zone")
	assert.Len(t, publicZone.RecordSet.ARecords, 4, "ARecords count mismatch in Public Zone")
	assert.Len(t, publicZone.RecordSet.CNAMERecords, 1, "CNAMERecords count mismatch in Public Zone")
	assert.Len(t, publicZone.RecordSet.MXRecords, 1, "MXRecords count mismatch in Public Zone")
	assert.Len(t, publicZone.RecordSet.TXTRecords, 1, "TXTRecords count mismatch in Public Zone")

	// Internal Zone Assertions
	internalZone := config.InternalServer.Zone
	assert.Equal(t, "trusted-platform.internal.", internalZone.Name)
	assert.Equal(t, "Internal zone for trusted-platform.internal", internalZone.Description)
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

	// Step 3: Assert Datastore configurations match
	assert.Equal(t, DefaultConfig.Datastore, deserializedConfig.Datastore, "Datastore configuration mismatch")

	// Step 4: Assert PublicServer configurations match
	publicZone := deserializedConfig.PublicServer.Zone
	assert.Equal(t, DefaultConfig.PublicServer.Zone.Name, publicZone.Name, "PublicServer.Zone.Name mismatch")
	assert.Equal(t, DefaultConfig.PublicServer.Zone.Description, publicZone.Description, "PublicServer.Zone.Description mismatch")
	assert.Len(t, publicZone.RecordSet.NSRecords, 3, "PublicServer.Zone NSRecords count mismatch")
	assert.Len(t, publicZone.RecordSet.ARecords, 4, "PublicServer.Zone ARecords count mismatch")
	assert.Len(t, publicZone.RecordSet.CNAMERecords, 1, "PublicServer.Zone CNAMERecords count mismatch")
	assert.Len(t, publicZone.RecordSet.MXRecords, 1, "PublicServer.Zone MXRecords count mismatch")
	assert.Len(t, publicZone.RecordSet.TXTRecords, 1, "PublicServer.Zone TXTRecords count mismatch")

	// Assert PublicServer individual records
	assert.Equal(t, DefaultConfig.PublicServer.Zone.RecordSet.NSRecords, publicZone.RecordSet.NSRecords, "PublicServer.Zone NSRecords mismatch")
	assert.Equal(t, DefaultConfig.PublicServer.Zone.RecordSet.ARecords, publicZone.RecordSet.ARecords, "PublicServer.Zone ARecords mismatch")
	assert.Equal(t, DefaultConfig.PublicServer.Zone.RecordSet.CNAMERecords, publicZone.RecordSet.CNAMERecords, "PublicServer.Zone CNAMERecords mismatch")
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
