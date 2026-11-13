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
	"github.com/miekg/dns"
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

// negativeAnswerZone is a zone with one name defined below the apex and an SOA
// whose MINIMUM bounds negative caching more tightly than its own TTL.
func negativeAnswerZone() *entities.Zone {
	return &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.0.2.1", TTL: 3600},
				{Name: "deep.host", Value: "192.0.2.2", TTL: 3600},
			},
			SOARecord: entities.SOARecord{
				MName:      "ns1.example.com.",
				RName:      "hostmaster.example.com.",
				Serial:     1,
				MinimumTTL: 300,
				TTL:        3600,
			},
		},
	}
}

func questionFor(qname string, qtype uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	return req
}

// TestBuildResponse_Answer asserts a query that matched records is answered
// authoritatively, with nothing in the authority section.
func TestBuildResponse_Answer(t *testing.T) {
	zone := negativeAnswerZone()
	rrs, err := parseQueriedRecord(dns.TypeA, "www.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	msg := buildResponse(questionFor("www.example.com.", dns.TypeA), dns.TypeA, "www.example.com.", zone, rrs)

	assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
	assert.True(t, msg.Authoritative, "an authoritative server must set the AA bit")
	require.Len(t, msg.Answer, 1)
	assert.Empty(t, msg.Ns)
}

// withServedZone points the plugin at an in-memory DAO holding zone, with a
// public port the test writer's local address (9053) never matches.
func withServedZone(t *testing.T, zone *entities.Zone) {
	t.Helper()
	prevDAO, prevConf := zoneDAO, Configuration
	zDAO := newMemoryZoneDAO()
	zDAO.addZone(zone)
	zoneDAO = zDAO
	Configuration = &Config{Logger: logging.DefaultLogger(), PublicServer: &PublicServer{Port: 53}}
	t.Cleanup(func() { zoneDAO, Configuration = prevDAO, prevConf })
}

func TestServeDNS_UpdateIsNotImplemented(t *testing.T) {
	withServedZone(t, negativeAnswerZone())

	update := new(dns.Msg)
	update.SetUpdate("example.com.")
	update.Insert([]dns.RR{mustA("www.example.com.", "192.0.2.9")})

	w := &fakeResponseWriter{}
	rcode, err := TrustedPlatformPlugin{}.ServeDNS(context.Background(), w, update)

	require.NoError(t, err)
	assert.Equal(t, dns.RcodeNotImplemented, rcode, "RFC 1035 §4.1.1 RCODE 4 for an UPDATE (RFC 2136 §2)")
	assert.Nil(t, w.msg, "the zone section must not be answered as a query; the CoreDNS server writes NOTIMP")
}

func TestServeDNS_QueryWithoutQuestionIsFormatError(t *testing.T) {
	withServedZone(t, negativeAnswerZone())

	query := new(dns.Msg)
	query.Id = dns.Id()

	w := &fakeResponseWriter{}
	rcode, err := TrustedPlatformPlugin{}.ServeDNS(context.Background(), w, query)

	require.NoError(t, err)
	assert.Equal(t, dns.RcodeFormatError, rcode, "RFC 1035 §4.1.1 RCODE 1 for a query with no question")
	assert.Nil(t, w.msg, "the CoreDNS server writes FORMERR")
}

func TestServeDNS_QueryStillResolves(t *testing.T) {
	withServedZone(t, negativeAnswerZone())

	w := &fakeResponseWriter{}
	rcode, err := TrustedPlatformPlugin{}.ServeDNS(context.Background(), w, query("www.example.com.", dns.TypeA))

	require.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, rcode)
	require.NotNil(t, w.msg)
	require.Len(t, w.msg.Answer, 1)
	assert.Equal(t, "192.0.2.1", w.msg.Answer[0].(*dns.A).A.String())
}

// TestBuildResponse_NameError asserts a name the zone does not define is
// NXDOMAIN with the zone SOA in the authority section, not the empty NOERROR
// the server used to send. The negative-caching TTL is the lesser of the SOA
// TTL and its MINIMUM (RFC 2308 §3, §5).
func TestBuildResponse_NameError(t *testing.T) {
	zone := negativeAnswerZone()
	qname := "www.anything.example.com."

	rrs, err := parseQueriedRecord(dns.TypeA, qname, zone)
	require.NoError(t, err)
	require.Empty(t, rrs)

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, rrs)

	assert.Equal(t, dns.RcodeNameError, msg.Rcode)
	assert.True(t, msg.Authoritative)
	assert.Empty(t, msg.Answer)
	require.Len(t, msg.Ns, 1)
	soa, ok := msg.Ns[0].(*dns.SOA)
	require.True(t, ok)
	assert.Equal(t, "example.com.", soa.Hdr.Name)
	assert.Equal(t, uint32(300), soa.Hdr.Ttl)
}

// TestBuildResponse_NoData asserts a name that exists but holds no record of
// the queried type is NOERROR with an empty answer, never NXDOMAIN
// (RFC 2308 §2.2).
func TestBuildResponse_NoData(t *testing.T) {
	zone := negativeAnswerZone()
	qname := "www.example.com."

	rrs, err := parseQueriedRecord(dns.TypeMX, qname, zone)
	require.NoError(t, err)
	require.Empty(t, rrs)

	msg := buildResponse(questionFor(qname, dns.TypeMX), dns.TypeMX, qname, zone, rrs)

	assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
	assert.Empty(t, msg.Answer)
	require.Len(t, msg.Ns, 1)
	assert.Equal(t, uint32(300), msg.Ns[0].Header().Ttl)
}

// TestBuildResponse_EmptyNonTerminal asserts an interior node with no records
// of its own is NODATA and not NXDOMAIN: host.example.com. exists because
// deep.host.example.com. does (RFC 1034 §4.3.2).
func TestBuildResponse_EmptyNonTerminal(t *testing.T) {
	zone := negativeAnswerZone()
	qname := "host.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, nil)

	assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
	assert.Empty(t, msg.Answer)
}

// TestBuildResponse_ApexNoData asserts the zone apex itself is always an
// existing name, even when it owns no record of the queried type.
func TestBuildResponse_ApexNoData(t *testing.T) {
	zone := negativeAnswerZone()

	msg := buildResponse(questionFor("example.com.", dns.TypeAAAA), dns.TypeAAAA, "example.com.", zone, nil)

	assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
	require.Len(t, msg.Ns, 1)
}

// TestBuildResponse_NoSOAConfigured asserts a zone with no SOA still returns
// the right rcode, with an empty authority section: there is nothing
// authoritative to cite for the denial.
func TestBuildResponse_NoSOAConfigured(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{{Name: "www", Value: "192.0.2.1", TTL: 3600}},
		},
	}

	msg := buildResponse(questionFor("missing.example.com.", dns.TypeA), dns.TypeA, "missing.example.com.", zone, nil)

	assert.Equal(t, dns.RcodeNameError, msg.Rcode)
	assert.Empty(t, msg.Ns)
}

// TestNegativeSOA_TTLSelection covers the negative-caching TTL rule against
// the combinations an operator can configure.
func TestNegativeSOA_TTLSelection(t *testing.T) {
	cases := []struct {
		name       string
		zoneTTL    uint32
		ttl        uint32
		minimumTTL uint32
		want       uint32
	}{
		{"minimum is lower", 0, 3600, 300, 300},
		{"record ttl is lower", 0, 60, 300, 60},
		{"no minimum configured", 0, 3600, 0, 3600},
		{"no record ttl configured", 0, 0, 300, 300},
		// A zone that sets only the top-level ttl must not have its denials
		// cached against a TTL of zero.
		{"record ttl inherited from the zone", 1800, 0, 0, 1800},
		{"minimum still wins over the inherited ttl", 1800, 0, 300, 300},
		{"inherited ttl wins over a larger minimum", 900, 0, 7200, 900},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			zone := &entities.Zone{
				Name: "example.com.",
				TTL:  c.zoneTTL,
				RecordSet: entities.RecordSet{
					SOARecord: entities.SOARecord{
						MName:      "ns1.example.com.",
						RName:      "hostmaster.example.com.",
						TTL:        c.ttl,
						MinimumTTL: c.minimumTTL,
					},
				},
			}
			soa := negativeSOA(zone)
			require.NotNil(t, soa)
			assert.Equal(t, c.want, soa.Hdr.Ttl)
		})
	}
}

// TestNegativeSOA_Unconfigured asserts a zone with no SOA yields no authority
// record rather than one naming an empty primary server.
func TestNegativeSOA_Unconfigured(t *testing.T) {
	assert.Nil(t, negativeSOA(&entities.Zone{Name: "example.com."}))
}

// delegatingZone holds a delegation to a child zone alongside its own data,
// so a query below the delegation can be told apart from one that simply does
// not exist.
func delegatingZone() *entities.Zone {
	return &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.0.2.1", TTL: 3600},
				// Glue: the child's nameservers live inside the zone it is
				// delegated, so only the parent can supply their addresses.
				{Name: "ns1.child", Value: "192.0.2.10", TTL: 3600},
				{Name: "ns2.child", Value: "192.0.2.11", TTL: 3600},
			},
			AAAARecords: []*entities.AAAARecord{
				{Name: "ns1.child", Value: "2001:db8::10", TTL: 3600},
			},
			NSRecords: []*entities.NSRecord{
				{Name: "@", Value: "ns1.example.com.", TTL: 3600},
				{Name: "child", Value: "ns1.child.example.com.", TTL: 3600},
				{Name: "child", Value: "ns2.child.example.com.", TTL: 3600},
				{Name: "deep.child", Value: "ns1.deep.child.example.com.", TTL: 3600},
				// A misconfigured owner outside the zone: it delegates
				// nothing from here and must not swallow the whole zone.
				{Name: "com.", Value: "ns1.gtld-servers.net.", TTL: 3600},
			},
			SOARecord: entities.SOARecord{
				MName:      "ns1.example.com.",
				RName:      "hostmaster.example.com.",
				MinimumTTL: 300,
				TTL:        3600,
			},
		},
	}
}

// TestBuildResponse_Referral asserts a name below a delegation is referred to
// the child's nameservers, not denied. The parent holds the NS records but is
// not authoritative for names beneath them (RFC 1034 §4.3.2 step 3b), so
// NXDOMAIN there would let resolvers cache a false non-existence.
func TestBuildResponse_Referral(t *testing.T) {
	zone := delegatingZone()
	qname := "www.child.example.com."

	rrs, err := parseQueriedRecord(dns.TypeA, qname, zone)
	require.NoError(t, err)
	require.Empty(t, rrs)

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, rrs)

	assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
	assert.False(t, msg.Authoritative, "a referral must not claim authority")
	assert.Empty(t, msg.Answer)
	require.Len(t, msg.Ns, 2)
	for _, rr := range msg.Ns {
		ns, ok := rr.(*dns.NS)
		require.True(t, ok, "the authority section of a referral carries NS records, not the SOA")
		assert.Equal(t, "child.example.com.", ns.Hdr.Name)
	}
}

// TestBuildResponse_ReferralClosestDelegation asserts the closest enclosing
// delegation wins — the child zone that actually holds the name.
func TestBuildResponse_ReferralClosestDelegation(t *testing.T) {
	zone := delegatingZone()
	qname := "host.deep.child.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, nil)

	require.Len(t, msg.Ns, 1)
	assert.Equal(t, "deep.child.example.com.", msg.Ns[0].Header().Name)
	assert.Equal(t, "ns1.deep.child.example.com.", msg.Ns[0].(*dns.NS).Ns)
}

// TestBuildResponse_ApexNSIsNotADelegation asserts the zone's own apex NS
// RRset does not turn every miss into a referral: it names this server, and
// delegates nothing.
func TestBuildResponse_ApexNSIsNotADelegation(t *testing.T) {
	zone := delegatingZone()
	qname := "missing.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, nil)

	assert.Equal(t, dns.RcodeNameError, msg.Rcode)
	assert.True(t, msg.Authoritative)
	require.Len(t, msg.Ns, 1)
	assert.IsType(t, &dns.SOA{}, msg.Ns[0])
}

func TestDelegationFor(t *testing.T) {
	zone := delegatingZone()

	owner, ns := delegationFor(zone, "child.example.com.")
	assert.Equal(t, "child.example.com.", owner, "the delegation point itself is at the cut")
	assert.Len(t, ns, 2)

	owner, ns = delegationFor(zone, "a.b.child.example.com.")
	assert.Equal(t, "child.example.com.", owner)
	assert.Len(t, ns, 2)

	for _, qname := range []string{"example.com.", "www.example.com.", "notchild.example.com."} {
		owner, ns = delegationFor(zone, qname)
		assert.Empty(t, owner, qname)
		assert.Nil(t, ns, qname)
	}

	owner, ns = delegationFor(&entities.Zone{Name: "example.com."}, "www.example.com.")
	assert.Empty(t, owner)
	assert.Nil(t, ns)
}

// TestBuildResponse_DSAtDelegationIsAnswered asserts a DS query at the cut is
// answered by the parent rather than referred. The DS RRset lives on the
// parent side (RFC 4035 §3.1.4.1), and an insecure delegation has to be able
// to say authoritatively that it has no DS — a referral there leaves every
// unsigned child unvalidatable.
func TestBuildResponse_DSAtDelegationIsAnswered(t *testing.T) {
	zone := delegatingZone()
	qname := "child.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeDS), dns.TypeDS, qname, zone, nil)

	assert.Equal(t, dns.RcodeSuccess, msg.Rcode, "the name exists — it is a delegation point")
	assert.True(t, msg.Authoritative, "the parent is authoritative for the DS RRset at the cut")
	require.Len(t, msg.Ns, 1)
	assert.IsType(t, &dns.SOA{}, msg.Ns[0], "a NODATA answer cites the SOA, not the child's NS")
}

// TestBuildResponse_DSBelowDelegationIsReferred asserts the DS exception is
// confined to the cut itself: a DS query for a name INSIDE the child zone is
// the child's to answer.
func TestBuildResponse_DSBelowDelegationIsReferred(t *testing.T) {
	zone := delegatingZone()
	qname := "grandchild.child.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeDS), dns.TypeDS, qname, zone, nil)

	assert.False(t, msg.Authoritative)
	require.Len(t, msg.Ns, 2)
	assert.IsType(t, &dns.NS{}, msg.Ns[0])
}

// TestBuildResponse_NonDSAtDelegationIsReferred asserts every other type at
// the cut is still a referral — the parent holds no data there.
func TestBuildResponse_NonDSAtDelegationIsReferred(t *testing.T) {
	zone := delegatingZone()
	qname := "child.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, nil)

	assert.False(t, msg.Authoritative)
	require.Len(t, msg.Ns, 2)
	assert.IsType(t, &dns.NS{}, msg.Ns[0])
}

// TestBuildResponse_ReferralCarriesGlue asserts an in-bailiwick referral ships
// the child nameservers' addresses. Without them the referral is a circular
// dependency: the resolver is told to ask ns1.child.example.com. and can only
// learn that name's address from the zone it was just referred to.
func TestBuildResponse_ReferralCarriesGlue(t *testing.T) {
	zone := delegatingZone()
	qname := "www.child.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, nil)

	require.Len(t, msg.Ns, 2)
	names := make(map[string]int, len(msg.Extra))
	for _, rr := range msg.Extra {
		names[rr.Header().Name]++
	}
	assert.Equal(t, 2, names["ns1.child.example.com."], "A and AAAA glue for ns1")
	assert.Equal(t, 1, names["ns2.child.example.com."], "A glue for ns2")
}

// TestBuildResponse_ReferralOmitsOutOfBailiwickGlue asserts the parent offers
// addresses only for nameservers inside the delegated zone. An address for any
// other name is not this zone's to give.
func TestBuildResponse_ReferralOmitsOutOfBailiwickGlue(t *testing.T) {
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{{Name: "ns1", Value: "192.0.2.1", TTL: 3600}},
			NSRecords: []*entities.NSRecord{
				{Name: "child", Value: "ns1.example.com.", TTL: 3600},
			},
		},
	}
	qname := "www.child.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, nil)

	require.Len(t, msg.Ns, 1)
	assert.Empty(t, msg.Extra,
		"ns1.example.com. is outside the delegated zone, so its address is not glue")
}

// TestDelegationFor_IgnoresOutOfZoneOwners asserts an NS owner outside the
// zone delegates nothing from here. Nothing constrains the stored owner today,
// and a misconfigured "com." would otherwise refer every name in the zone away
// instead of answering NXDOMAIN or NODATA.
func TestDelegationFor_IgnoresOutOfZoneOwners(t *testing.T) {
	zone := delegatingZone()

	owner, ns := delegationFor(zone, "missing.example.com.")
	assert.Empty(t, owner)
	assert.Nil(t, ns)

	msg := buildResponse(questionFor("missing.example.com.", dns.TypeA), dns.TypeA,
		"missing.example.com.", zone, nil)
	assert.Equal(t, dns.RcodeNameError, msg.Rcode)
}

// TestBuildResponse_DelegationBeatsParentData asserts the cut is found before
// any data at or below it. RFC 1034 §4.3.2 step 3(b) walks DOWN to the name
// and stops at the delegation, so an NS query for the cut and an A query for
// a glue record are referrals, not authoritative answers — glue belongs in the
// additional section, and a resolver must not cache it as authoritative.
func TestBuildResponse_DelegationBeatsParentData(t *testing.T) {
	zone := delegatingZone()

	// The parser does hold matching records for both of these.
	nsRRs, err := parseQueriedRecord(dns.TypeNS, "child.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, nsRRs, 2)
	glueRRs, err := parseQueriedRecord(dns.TypeA, "ns1.child.example.com.", zone)
	require.NoError(t, err)
	require.Len(t, glueRRs, 1)

	msg := buildResponse(questionFor("child.example.com.", dns.TypeNS), dns.TypeNS,
		"child.example.com.", zone, nsRRs)
	assert.False(t, msg.Authoritative, "the delegating NS RRset is not authoritative data")
	assert.Empty(t, msg.Answer)
	assert.Len(t, msg.Ns, 2)

	msg = buildResponse(questionFor("ns1.child.example.com.", dns.TypeA), dns.TypeA,
		"ns1.child.example.com.", zone, glueRRs)
	assert.False(t, msg.Authoritative)
	assert.Empty(t, msg.Answer, "glue is additional-section data, never an answer")
	assert.Len(t, msg.Ns, 2)
	assert.NotEmpty(t, msg.Extra)
}

// TestBuildResponse_DSAtDelegationStillAnswered asserts the DS exception
// survives the reordering: a DS RRset at the cut is parent-side data and is
// answered authoritatively.
func TestBuildResponse_DSAtDelegationStillAnswered(t *testing.T) {
	zone := delegatingZone()
	zone.RecordSet.DSRecords = []*entities.DSRecord{
		{Name: "child", KeyTag: 1234, Algorithm: 13, DigestType: 2, Digest: "abcd", TTL: 3600},
	}
	qname := "child.example.com."

	rrs, err := parseQueriedRecord(dns.TypeDS, qname, zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	msg := buildResponse(questionFor(qname, dns.TypeDS), dns.TypeDS, qname, zone, rrs)

	assert.True(t, msg.Authoritative)
	require.Len(t, msg.Answer, 1)
	assert.Equal(t, dns.TypeDS, msg.Answer[0].Header().Rrtype)
}

// legacyTemplateZone reproduces a zone seeded from a template older than
// 2026-09-02: the zone's own NS record stored under the control-plane
// hostname rather than the apex, alongside that hostname's real records.
// processZone never re-seeds a persisted zone, so upgraded nodes still hold
// this shape.
func legacyTemplateZone() *entities.Zone {
	return &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "cp", Value: "192.0.2.1", TTL: 3600},
				{Name: "@", Value: "192.0.2.1", TTL: 3600},
			},
			NSRecords: []*entities.NSRecord{
				{Name: "cp.example.com.", Value: "ns1.cp.example.com.", TTL: 3600},
			},
			MXRecords: []*entities.MXRecord{
				{Name: "cp.example.com.", Value: "mail.cp.example.com.", Priority: 10, TTL: 3600},
			},
			SOARecord: entities.SOARecord{
				MName: "ns1.example.com.", RName: "hostmaster.example.com.",
				MinimumTTL: 300, TTL: 3600,
			},
		},
	}
}

// TestBuildResponse_NSOwnerWithDataIsNotADelegation asserts an NS owner that
// also holds ordinary data is not read as a zone cut. Authoritative data and a
// cut cannot share an owner (RFC 2181 §6.1), and treating this shape as a
// delegation would stop upgraded nodes from answering their own control-plane
// name — the record they most need.
func TestBuildResponse_NSOwnerWithDataIsNotADelegation(t *testing.T) {
	zone := legacyTemplateZone()
	qname := "cp.example.com."

	owner, ns := delegationFor(zone, qname)
	assert.Empty(t, owner)
	assert.Nil(t, ns)

	rrs, err := parseQueriedRecord(dns.TypeA, qname, zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, rrs)

	assert.True(t, msg.Authoritative, "the zone still answers this name authoritatively")
	require.Len(t, msg.Answer, 1)
	assert.Equal(t, "cp.example.com.", msg.Answer[0].Header().Name)
}

// TestBuildResponse_NSOnlyOwnerIsADelegation is the other half: an owner
// holding NS and nothing else is a genuine cut and is referred.
func TestBuildResponse_NSOnlyOwnerIsADelegation(t *testing.T) {
	zone := legacyTemplateZone()
	zone.RecordSet.NSRecords = append(zone.RecordSet.NSRecords,
		&entities.NSRecord{Name: "child", Value: "ns1.child.example.com.", TTL: 3600})

	owner, ns := delegationFor(zone, "www.child.example.com.")
	assert.Equal(t, "child.example.com.", owner)
	require.Len(t, ns, 1)

	msg := buildResponse(questionFor("www.child.example.com.", dns.TypeA), dns.TypeA,
		"www.child.example.com.", zone, nil)
	assert.False(t, msg.Authoritative)
}

// TestBuildResponse_LegacyNSOwnerBelowIsNotReferred asserts names BELOW the
// misplaced NS owner are not referred either: with no cut there, they are
// ordinary names in this zone and get a normal negative answer.
func TestBuildResponse_LegacyNSOwnerBelowIsNotReferred(t *testing.T) {
	zone := legacyTemplateZone()
	qname := "api.cp.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, nil)

	assert.True(t, msg.Authoritative)
	assert.Equal(t, dns.RcodeNameError, msg.Rcode)
}

// aliasZone holds the alias shapes a zone can carry: an in-zone alias with a
// target that resolves, one whose target holds no record of the queried type,
// an alias out of the zone, a two-hop chain, and a cycle.
func aliasZone() *entities.Zone {
	return &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "app", Value: "192.0.2.5", TTL: 3600},
			},
			AAAARecords: []*entities.AAAARecord{
				{Name: "app", Value: "2001:db8::5", TTL: 3600},
			},
			CNAMERecords: []*entities.CNAMERecord{
				{Name: "www", Value: "app.example.com.", TTL: 3600},
				{Name: "shop", Value: "shop.example.net.", TTL: 3600},
				{Name: "store", Value: "shop.example.com.", TTL: 3600},
				{Name: "mail", Value: "nowhere.example.com.", TTL: 3600},
				{Name: "loop", Value: "loop.example.com.", TTL: 3600},
			},
			SOARecord: entities.SOARecord{
				MName: "ns1.example.com.", RName: "hostmaster.example.com.",
				MinimumTTL: 300, TTL: 3600,
			},
		},
	}
}

// TestBuildResponse_CNAMEChased asserts a query for another type at an alias
// answers the CNAME and the target's records. A negative answer here would
// have resolvers cache "www has no address" for a name that resolves to one.
func TestBuildResponse_CNAMEChased(t *testing.T) {
	zone := aliasZone()
	qname := "www.example.com."

	rrs, err := parseQueriedRecord(dns.TypeA, qname, zone)
	require.NoError(t, err)
	require.Empty(t, rrs)

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, rrs)

	assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
	assert.True(t, msg.Authoritative)
	assert.Empty(t, msg.Ns, "an answered query needs no negative-cache SOA")
	require.Len(t, msg.Answer, 2)
	cname, ok := msg.Answer[0].(*dns.CNAME)
	require.True(t, ok)
	assert.Equal(t, "www.example.com.", cname.Hdr.Name)
	assert.Equal(t, "app.example.com.", cname.Target)
	a, ok := msg.Answer[1].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "app.example.com.", a.Hdr.Name)
}

// TestBuildResponse_CNAMEChainFollowed asserts a multi-hop chain is followed
// to the record it ends at.
func TestBuildResponse_CNAMEChainFollowed(t *testing.T) {
	zone := aliasZone()
	zone.RecordSet.CNAMERecords = append(zone.RecordSet.CNAMERecords,
		&entities.CNAMERecord{Name: "alias", Value: "www.example.com.", TTL: 3600})
	qname := "alias.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, nil)

	require.Len(t, msg.Answer, 3)
	assert.Equal(t, "alias.example.com.", msg.Answer[0].Header().Name)
	assert.Equal(t, "www.example.com.", msg.Answer[1].Header().Name)
	assert.Equal(t, dns.TypeA, msg.Answer[2].Header().Rrtype)
}

// TestBuildResponse_CNAMEToNameWithoutType asserts a chain ending in this zone
// at a name owning no record of the queried type is the CNAME plus a
// negative-cache SOA — NODATA at the end of the chain, not a bare alias.
func TestBuildResponse_CNAMEToNameWithoutType(t *testing.T) {
	zone := aliasZone()
	qname := "mail.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, nil)

	require.Len(t, msg.Answer, 1)
	assert.IsType(t, &dns.CNAME{}, msg.Answer[0])
	require.Len(t, msg.Ns, 1)
	assert.IsType(t, &dns.SOA{}, msg.Ns[0])
}

// TestBuildResponse_CNAMEOutOfZone asserts an alias leaving the zone answers
// the CNAME alone: the resolver continues from the target, and citing this
// zone's SOA would invite it to cache a denial this zone cannot make.
func TestBuildResponse_CNAMEOutOfZone(t *testing.T) {
	zone := aliasZone()
	qname := "shop.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, nil)

	require.Len(t, msg.Answer, 1)
	assert.Equal(t, "shop.example.net.", msg.Answer[0].(*dns.CNAME).Target)
	assert.Empty(t, msg.Ns)
}

// TestBuildResponse_CNAMELoopTerminates asserts alias data that points at
// itself still produces an answer rather than spinning.
func TestBuildResponse_CNAMELoopTerminates(t *testing.T) {
	zone := aliasZone()
	qname := "loop.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, nil)

	require.NotEmpty(t, msg.Answer)
	assert.LessOrEqual(t, len(msg.Answer), maxCNAMEDepth)
	assert.IsType(t, &dns.CNAME{}, msg.Answer[0])
}

// TestBuildResponse_CNAMEQueryIsNotChased asserts a CNAME query is answered by
// the parser itself and never enters the chain: the alias IS the answer.
func TestBuildResponse_CNAMEQueryIsNotChased(t *testing.T) {
	zone := aliasZone()
	qname := "www.example.com."

	rrs, err := parseQueriedRecord(dns.TypeCNAME, qname, zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	msg := buildResponse(questionFor(qname, dns.TypeCNAME), dns.TypeCNAME, qname, zone, rrs)

	require.Len(t, msg.Answer, 1)
	assert.Equal(t, "app.example.com.", msg.Answer[0].(*dns.CNAME).Target)
}

// TestBuildResponse_NoCNAMEStillNegative asserts the alias path does not
// swallow ordinary negative answers.
func TestBuildResponse_NoCNAMEStillNegative(t *testing.T) {
	zone := aliasZone()

	msg := buildResponse(questionFor("missing.example.com.", dns.TypeA), dns.TypeA,
		"missing.example.com.", zone, nil)
	assert.Equal(t, dns.RcodeNameError, msg.Rcode)
	assert.Empty(t, msg.Answer)

	msg = buildResponse(questionFor("app.example.com.", dns.TypeMX), dns.TypeMX,
		"app.example.com.", zone, nil)
	assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
	assert.Empty(t, msg.Answer)
	assert.Len(t, msg.Ns, 1)
}

// TestBuildResponse_NSECAtDelegationIsAnswered asserts the NSEC a signed
// parent stores at the cut is answered, not referred. It is parent-side data
// proving the delegation exists, and a referral would put an RRset the zone
// actually holds out of reach of validators and DNSSEC tooling.
func TestBuildResponse_NSECAtDelegationIsAnswered(t *testing.T) {
	zone := delegatingZone()
	zone.RecordSet.NSECRecords = []*entities.NSECRecord{
		{
			Name:       "child",
			NextDomain: "www.example.com.",
			TypeBitMap: []uint16{dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC},
			TTL:        3600,
		},
	}
	qname := "child.example.com."

	rrs, err := parseQueriedRecord(dns.TypeNSEC, qname, zone)
	require.NoError(t, err)
	require.Len(t, rrs, 1)

	msg := buildResponse(questionFor(qname, dns.TypeNSEC), dns.TypeNSEC, qname, zone, rrs)

	assert.True(t, msg.Authoritative)
	require.Len(t, msg.Answer, 1)
	assert.Equal(t, dns.TypeNSEC, msg.Answer[0].Header().Rrtype)
}

// TestBuildResponse_NSECBelowDelegationIsReferred asserts the parent-side
// exemption stops at the cut: an NSEC inside the child zone is the child's.
func TestBuildResponse_NSECBelowDelegationIsReferred(t *testing.T) {
	zone := delegatingZone()
	qname := "www.child.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeNSEC), dns.TypeNSEC, qname, zone, nil)

	assert.False(t, msg.Authoritative)
	require.Len(t, msg.Ns, 2)
	assert.IsType(t, &dns.NS{}, msg.Ns[0])
}

// TestBuildResponse_CNAMEIntoDelegatedZoneStopsAtCut asserts an alias pointing
// into a delegated child ends the chain there. The parent's glue is not an
// answer, and its SOA is not a denial it may make for the child's names.
func TestBuildResponse_CNAMEIntoDelegatedZoneStopsAtCut(t *testing.T) {
	zone := delegatingZone()
	zone.RecordSet.CNAMERecords = []*entities.CNAMERecord{
		{Name: "alias", Value: "ns1.child.example.com.", TTL: 3600},
	}
	qname := "alias.example.com."

	msg := buildResponse(questionFor(qname, dns.TypeA), dns.TypeA, qname, zone, nil)

	require.Len(t, msg.Answer, 1)
	assert.IsType(t, &dns.CNAME{}, msg.Answer[0],
		"the parent's glue for the child's nameserver is not an answer")
	assert.Empty(t, msg.Ns, "the parent may not deny a name inside the child zone")
}
