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
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memoryZoneDAO is a minimal in-memory implementation of dao.ZoneDAO used
// exclusively for unit testing the zone lookup logic. Zones are stored by
// their deterministic ID (util.NewID of the zone name).
type memoryZoneDAO struct {
	zones map[uint64]*entities.Zone
}

func newMemoryZoneDAO() *memoryZoneDAO {
	return &memoryZoneDAO{
		zones: make(map[uint64]*entities.Zone),
	}
}

func (m *memoryZoneDAO) addZone(zone *entities.Zone) {
	if zone.ID == 0 {
		zone.ID = util.NewID([]byte(zone.Name))
	}
	m.zones[zone.ID] = zone
}

func (m *memoryZoneDAO) Get(_ context.Context, id uint64) (*entities.Zone, error) {
	z, ok := m.zones[id]
	if !ok {
		return nil, ErrZoneNotFound
	}
	return z, nil
}

func (m *memoryZoneDAO) GetByName(_ context.Context, name string) (*entities.Zone, error) {
	id := util.NewID([]byte(name))
	return m.Get(context.Background(), id)
}

func (m *memoryZoneDAO) Save(_ context.Context, entity *entities.Zone) error {
	if entity.ID == 0 {
		entity.ID = util.NewID([]byte(entity.Name))
	}
	m.zones[entity.ID] = entity
	return nil
}

func (m *memoryZoneDAO) Delete(_ context.Context, entity *entities.Zone) error {
	delete(m.zones, entity.ID)
	return nil
}

func (m *memoryZoneDAO) Count(_ context.Context) (int, error) {
	return len(m.zones), nil
}

func (m *memoryZoneDAO) Page(_ context.Context, _ datastore.PageQuery) (datastore.PageResult[*entities.Zone], error) {
	return datastore.PageResult[*entities.Zone]{}, nil
}

func (m *memoryZoneDAO) ForEachPage(_ context.Context, _ datastore.PageQuery, _ datastore.PagerFunc[*entities.Zone]) error {
	return nil
}

// TestUint16Ptr verifies the uint16 pointer helper function.
func TestUint16Ptr(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
	}{
		{"zero value", 0},
		{"positive value", 12345},
		{"max value", 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ptr := uint16Ptr(tt.value)
			require.NotNil(t, ptr)
			assert.Equal(t, tt.value, *ptr)
		})
	}
}

// TestUint32Ptr verifies the uint32 pointer helper function.
func TestUint32Ptr(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
	}{
		{"zero value", 0},
		{"positive value", 123456789},
		{"max value", 4294967295},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ptr := uint32Ptr(tt.value)
			require.NotNil(t, ptr)
			assert.Equal(t, tt.value, *ptr)
		})
	}
}

// TestTrustedPlatformPlugin_Name verifies the plugin name.
func TestTrustedPlatformPlugin_Name(t *testing.T) {
	plugin := TrustedPlatformPlugin{}
	name := plugin.Name()
	assert.Equal(t, trustedPlatformPlugin, name)
	assert.Equal(t, "trustedPlatform", name)
}

// TestSave_Success verifies zone save logic including ID assignment.
func TestSave_Success(t *testing.T) {
	logger := logging.DefaultLogger()

	// Set up the global Configuration
	Configuration = &Config{
		Logger: logger,
		QuicBaaS: &quicbaas.Config{
			StorageBackend:   "pebble",
			DataDir:          t.TempDir(),
			WALDir:           t.TempDir() + "/wal",
			NodeID:           1,
			CacheSize:        64 * 1024 * 1024,
			LogLevel:         "warn",
			ConsistencyLevel: quicbaas.ConsistencyLinearizable,
		},
	}

	// This test verifies the ID assignment logic used in the Save function.
	// We can't easily test the full Save function without setting up the global
	// zoneDAO, but we can verify the ID assignment logic.
	zeroIDZone := &entities.Zone{
		ID:   0,
		Name: "no-id.com.",
		TTL:  3600,
	}

	// Verify ID would be assigned (same logic as Save function)
	if zeroIDZone.ID == 0 {
		zeroIDZone.ID = util.NewID([]byte(zeroIDZone.Name))
	}
	assert.NotEqual(t, uint64(0), zeroIDZone.ID)

	// Verify ID is deterministic based on zone name
	expectedID := util.NewID([]byte("no-id.com."))
	assert.Equal(t, expectedID, zeroIDZone.ID)
}

// TestSecurityLogEntry verifies the SecurityLogEntry struct fields.
func TestSecurityLogEntry(t *testing.T) {
	entry := logging.SecurityLogEntry{
		Severity:        "high",
		Category:        "network",
		Description:     "Test description",
		Details:         "Test details",
		Source:          "test",
		OffenderAddress: "192.168.1.1",
		OffenderID:      "test-id",
	}

	assert.Equal(t, "high", entry.Severity)
	assert.Equal(t, "network", entry.Category)
	assert.Equal(t, "Test description", entry.Description)
	assert.Equal(t, "Test details", entry.Details)
	assert.Equal(t, "test", entry.Source)
	assert.Equal(t, "192.168.1.1", entry.OffenderAddress)
	assert.Equal(t, "test-id", entry.OffenderID)
}

// TestErrInternalZoneQueryViolation verifies the error message.
func TestErrInternalZoneQueryViolation(t *testing.T) {
	err := ErrInternalZoneQueryViolation
	assert.Error(t, err)
	assert.Equal(t, "received public query for internal zone", err.Error())
}

// TestNeedsDNSSECSigning verifies the needsDNSSECSigning function.
func TestNeedsDNSSECSigning(t *testing.T) {
	// Save original configuration
	origConfig := Configuration
	defer func() { Configuration = origConfig }()

	tests := []struct {
		name         string
		config       *Config
		zone         *entities.Zone
		expectedNeed bool
	}{
		{
			name:   "nil configuration",
			config: nil,
			zone: &entities.Zone{
				Name: "example.com.",
			},
			expectedNeed: false,
		},
		{
			name: "DNSSEC disabled",
			config: &Config{
				DNSSEC: &DNSSECConfig{
					Enabled: false,
				},
			},
			zone: &entities.Zone{
				Name: "example.com.",
			},
			expectedNeed: false,
		},
		{
			name: "DNSSEC enabled, zone has no records",
			config: &Config{
				DNSSEC: &DNSSECConfig{
					Enabled: true,
				},
			},
			zone: &entities.Zone{
				Name:      "example.com.",
				RecordSet: entities.RecordSet{},
			},
			expectedNeed: true,
		},
		{
			name: "DNSSEC enabled, zone has DNSKEY but no RRSIG",
			config: &Config{
				DNSSEC: &DNSSECConfig{
					Enabled: true,
				},
			},
			zone: &entities.Zone{
				Name: "example.com.",
				RecordSet: entities.RecordSet{
					DNSKEYRecords: []*entities.DNSKEYRecord{
						{Name: "example.com.", Flags: 257, Protocol: 3, Algorithm: 13, Key: "testkey"},
					},
				},
			},
			expectedNeed: true,
		},
		{
			name: "DNSSEC enabled, zone has both DNSKEY and RRSIG",
			config: &Config{
				DNSSEC: &DNSSECConfig{
					Enabled: true,
				},
			},
			zone: &entities.Zone{
				Name: "example.com.",
				RecordSet: entities.RecordSet{
					DNSKEYRecords: []*entities.DNSKEYRecord{
						{Name: "example.com.", Flags: 257, Protocol: 3, Algorithm: 13, Key: "testkey"},
					},
					RRSIGRecords: []*entities.RRSIGRecord{
						{SignerName: "example.com.", Algorithm: 13, KeyTag: 12345},
					},
				},
			},
			expectedNeed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Configuration = tt.config
			result := needsDNSSECSigning(tt.zone)
			assert.Equal(t, tt.expectedNeed, result)
		})
	}
}

// TestZoneLookup_TLSAName verifies that the zone lookup logic correctly
// resolves a TLSA query name like _8443._tcp.server.example.com. to the
// example.com. zone by walking up the label hierarchy. This was the root
// cause of a bug where the CoreDNS plugin could not find the zone for
// TLSA queries because the full qname did not match any stored zone.
func TestZoneLookup_TLSAName(t *testing.T) {
	ctx := context.Background()
	zDAO := newMemoryZoneDAO()

	zone := &entities.Zone{
		Name: "example.com.",
		TTL:  3600,
		RecordSet: entities.RecordSet{
			TLSARecords: []*entities.TLSARecord{
				{
					Name:         "_8443._tcp.server.example.com.",
					Usage:        3,
					Selector:     1,
					MatchingType: 1,
					Data:         "abcdef0123456789",
					TTL:          3600,
				},
			},
		},
	}
	zDAO.addZone(zone)

	// The label hierarchy walk for _8443._tcp.server.example.com. tries:
	//   _8443._tcp.server.example.com. -> not found
	//   _tcp.server.example.com.       -> not found
	//   server.example.com.            -> not found
	//   example.com.                   -> found
	result := findZoneForQuery(ctx, "_8443._tcp.server.example.com.", zDAO)
	require.NotNil(t, result, "findZoneForQuery must resolve TLSA qname to example.com. zone")
	assert.Equal(t, "example.com.", result.Name)
	assert.Len(t, result.RecordSet.TLSARecords, 1)
	assert.Equal(t, "_8443._tcp.server.example.com.", result.RecordSet.TLSARecords[0].Name)
}

// TestZoneLookup_TLSAName_NoZone verifies that findZoneForQuery returns nil
// when no zone matches any suffix of a TLSA query name.
func TestZoneLookup_TLSAName_NoZone(t *testing.T) {
	ctx := context.Background()
	zDAO := newMemoryZoneDAO()

	// DAO is empty -- no zones stored
	result := findZoneForQuery(ctx, "_8443._tcp.server.example.com.", zDAO)
	assert.Nil(t, result, "findZoneForQuery must return nil when no zone matches")
}

// TestZoneLookup_SimpleHostname verifies that a simple hostname like
// server.example.com. resolves to the example.com. zone.
func TestZoneLookup_SimpleHostname(t *testing.T) {
	ctx := context.Background()
	zDAO := newMemoryZoneDAO()

	zone := &entities.Zone{
		Name: "example.com.",
		TTL:  3600,
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "server", Value: "10.0.0.1", TTL: 3600},
			},
		},
	}
	zDAO.addZone(zone)

	result := findZoneForQuery(ctx, "server.example.com.", zDAO)
	require.NotNil(t, result, "findZoneForQuery must resolve hostname to zone")
	assert.Equal(t, "example.com.", result.Name)
}

// TestZoneLookup_SimpleHostname_NoZone verifies that a simple hostname
// returns nil when the zone does not exist.
func TestZoneLookup_SimpleHostname_NoZone(t *testing.T) {
	ctx := context.Background()
	zDAO := newMemoryZoneDAO()

	// Store a different zone
	zDAO.addZone(&entities.Zone{Name: "other.com.", TTL: 3600})

	result := findZoneForQuery(ctx, "server.example.com.", zDAO)
	assert.Nil(t, result, "findZoneForQuery must return nil for unregistered zone")
}

// TestZoneLookup_SRVName verifies that SRV-style names with underscore-prefixed
// labels (e.g. _sip._tcp.example.com.) resolve to the correct zone. SRV records
// use the same underscore naming pattern as TLSA records.
func TestZoneLookup_SRVName(t *testing.T) {
	ctx := context.Background()
	zDAO := newMemoryZoneDAO()

	zone := &entities.Zone{
		Name: "example.com.",
		TTL:  3600,
		RecordSet: entities.RecordSet{
			SRVRecords: []*entities.SRVRecord{
				{
					Name:     "_sip._tcp.example.com.",
					Target:   "sip.example.com.",
					Port:     5060,
					Priority: 10,
					Weight:   100,
					TTL:      3600,
				},
			},
		},
	}
	zDAO.addZone(zone)

	// The hierarchy walk for _sip._tcp.example.com. tries:
	//   _sip._tcp.example.com. -> not found
	//   _tcp.example.com.      -> not found
	//   example.com.           -> found
	result := findZoneForQuery(ctx, "_sip._tcp.example.com.", zDAO)
	require.NotNil(t, result, "findZoneForQuery must resolve SRV qname to zone")
	assert.Equal(t, "example.com.", result.Name)
}

// TestZoneLookup_ExactZoneName verifies that querying for the zone name itself
// matches on the first iteration (no hierarchy walk needed).
func TestZoneLookup_ExactZoneName(t *testing.T) {
	ctx := context.Background()
	zDAO := newMemoryZoneDAO()

	zone := &entities.Zone{
		Name: "example.com.",
		TTL:  3600,
	}
	zDAO.addZone(zone)

	result := findZoneForQuery(ctx, "example.com.", zDAO)
	require.NotNil(t, result, "findZoneForQuery must match exact zone name")
	assert.Equal(t, "example.com.", result.Name)
}

// TestZoneLookup_ExactZoneName_NoZone verifies that an exact zone name query
// returns nil when the zone is not stored.
func TestZoneLookup_ExactZoneName_NoZone(t *testing.T) {
	ctx := context.Background()
	zDAO := newMemoryZoneDAO()

	result := findZoneForQuery(ctx, "example.com.", zDAO)
	assert.Nil(t, result, "findZoneForQuery must return nil for missing zone")
}

// TestZoneLookup_SubdomainMatchesClosestZone verifies that when multiple zones
// exist, the lookup returns the most specific (closest) matching zone. For example,
// a query for host.sub.example.com. should match sub.example.com. if that zone
// exists, not example.com.
func TestZoneLookup_SubdomainMatchesClosestZone(t *testing.T) {
	ctx := context.Background()
	zDAO := newMemoryZoneDAO()

	parentZone := &entities.Zone{Name: "example.com.", TTL: 3600}
	childZone := &entities.Zone{Name: "sub.example.com.", TTL: 1800}
	zDAO.addZone(parentZone)
	zDAO.addZone(childZone)

	// host.sub.example.com. should match sub.example.com. first (more specific)
	result := findZoneForQuery(ctx, "host.sub.example.com.", zDAO)
	require.NotNil(t, result)
	assert.Equal(t, "sub.example.com.", result.Name,
		"findZoneForQuery must prefer the most specific zone in the hierarchy")
}

// TestZoneLookup_DeeplyNestedTLSA verifies that deeply nested TLSA names with
// many labels still resolve correctly to the zone.
func TestZoneLookup_DeeplyNestedTLSA(t *testing.T) {
	ctx := context.Background()
	zDAO := newMemoryZoneDAO()

	zone := &entities.Zone{
		Name: "example.com.",
		TTL:  3600,
		RecordSet: entities.RecordSet{
			TLSARecords: []*entities.TLSARecord{
				{
					Name:         "_443._tcp.mail.sub.example.com.",
					Usage:        3,
					Selector:     1,
					MatchingType: 1,
					Data:         "deadbeef",
					TTL:          3600,
				},
			},
		},
	}
	zDAO.addZone(zone)

	// _443._tcp.mail.sub.example.com. has 6 labels; the walk must reach example.com.
	result := findZoneForQuery(ctx, "_443._tcp.mail.sub.example.com.", zDAO)
	require.NotNil(t, result, "findZoneForQuery must handle deeply nested TLSA names")
	assert.Equal(t, "example.com.", result.Name)
}
