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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file save zones through the Service into the
// quicbaas-backed Datastore and read them back, asserting that every zone
// field and every record type survives the round trip, including updates
// and removals made by a later Save.

const persistenceTestTenant = "platform"

// newPersistenceTestService returns a Service over a fresh in-memory datastore.
func newPersistenceTestService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(&Params{
		TenantID:  persistenceTestTenant,
		Config:    &Config{},
		Datastore: createTestDatastore(t),
	})
	require.NoError(t, err)
	return svc
}

// newPersistenceTestZone returns a zone with an SOA, two NS and two A records.
func newPersistenceTestZone(name string, internal bool) *entities.Zone {
	return &entities.Zone{
		ID:          util.NewID([]byte(name)),
		Name:        name,
		TenantID:    persistenceTestTenant,
		TTL:         3600,
		Description: "Test zone for " + name,
		Internal:    internal,
		RecordSet: entities.RecordSet{
			SOARecord: *NewSOARecord(name, "ns1."+name, "hostmaster."+name,
				2024010101, 7200, 3600, 1209600, 86400, 3600),
			NSRecords: []*entities.NSRecord{
				{Name: name, Value: "ns1." + name, TTL: 3600},
				{Name: name, Value: "ns2." + name, TTL: 3600},
			},
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.168.1.100", TTL: 300},
				{Name: "mail", Value: "192.168.1.101", TTL: 300},
			},
		},
	}
}

func hexSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestService_Save_PersistsZoneFields(t *testing.T) {
	svc := newPersistenceTestService(t)
	ctx := context.Background()

	zone := newPersistenceTestZone("example.com.", false)
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zone.Name)
	require.NoError(t, err)

	assert.Equal(t, zone.Name, retrieved.Name)
	assert.Equal(t, zone.TTL, retrieved.TTL)
	assert.Equal(t, zone.Description, retrieved.Description)
	assert.False(t, retrieved.Internal)
	assert.Equal(t, zone.RecordSet.SOARecord, retrieved.RecordSet.SOARecord)
}

func TestService_Save_UpdatesZone(t *testing.T) {
	svc := newPersistenceTestService(t)
	ctx := context.Background()

	zone := newPersistenceTestZone("update-test.com.", false)
	require.NoError(t, svc.Save(ctx, zone))

	zone.TTL = 7200
	zone.Description = "Updated description"
	zone.Internal = true
	zone.RecordSet.SOARecord.Serial = 2024010102
	zone.RecordSet.SOARecord.Refresh = 14400
	zone.RecordSet.SOARecord.Retry = 1800
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zone.Name)
	require.NoError(t, err)

	assert.Equal(t, uint32(7200), retrieved.TTL)
	assert.Equal(t, "Updated description", retrieved.Description)
	assert.True(t, retrieved.Internal)
	assert.Equal(t, uint32(2024010102), retrieved.RecordSet.SOARecord.Serial)
	assert.Equal(t, uint32(14400), retrieved.RecordSet.SOARecord.Refresh)
	assert.Equal(t, uint32(1800), retrieved.RecordSet.SOARecord.Retry)
}

// TestService_Save_PersistsEveryRecordType saves a zone holding every record
// kind in one Save, with the CAA flags and tags and the TLSA usage, selector
// and matching-type values of RFC 6844 and RFC 6698 §2.1, and expects the
// record set back field for field.
func TestService_Save_PersistsEveryRecordType(t *testing.T) {
	svc := newPersistenceTestService(t)
	ctx := context.Background()

	zoneName := "recordset-persistence.internal."
	sha512Sum := sha512.Sum512([]byte("subject-public-key-info"))
	zone := newPersistenceTestZone(zoneName, true)
	zone.RecordSet.ARecords = append(zone.RecordSet.ARecords,
		&entities.ARecord{Name: "@", Value: "192.168.1.1", TTL: 3600})
	zone.RecordSet.AAAARecords = []*entities.AAAARecord{
		{Name: "www", Value: "2001:db8::1", TTL: 300},
	}
	zone.RecordSet.CNAMERecords = []*entities.CNAMERecord{
		{Name: "blog", Value: "www." + zoneName, TTL: 300},
	}
	zone.RecordSet.MXRecords = []*entities.MXRecord{
		{Name: zoneName, Value: "mail." + zoneName, Priority: 10, TTL: 3600},
	}
	zone.RecordSet.TXTRecords = []*entities.TXTRecord{
		{Name: zoneName, Value: "v=spf1 include:_spf.example.com ~all", TTL: 3600},
	}
	zone.RecordSet.SRVRecords = []*entities.SRVRecord{
		{Name: "_ldap._tcp." + zoneName, Target: "ldap." + zoneName, Port: 389, Priority: 10, Weight: 100, TTL: 3600},
	}
	zone.RecordSet.CAARecords = []*entities.CAARecord{
		{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600},
		{Name: "@", Flags: 0, Tag: "issuewild", Value: "digicert.com", TTL: 3600},
		{Name: "@", Flags: 0, Tag: "iodef", Value: "mailto:security@" + zoneName, TTL: 3600},
		{Name: "secure", Flags: 128, Tag: "issue", Value: "privateca.example.com", TTL: 3600},
	}
	zone.RecordSet.TLSARecords = []*entities.TLSARecord{
		// PKIX-TA, PKIX-EE, DANE-TA and DANE-EE usages.
		{Name: "_443._tcp.pkix-ta." + zoneName, Usage: 0, Selector: 1, MatchingType: 1, Data: hexSHA256("pkix-ta"), TTL: 3600},
		{Name: "_443._tcp.pkix-ee." + zoneName, Usage: 1, Selector: 1, MatchingType: 1, Data: hexSHA256("pkix-ee"), TTL: 3600},
		{Name: "_443._tcp.dane-ta." + zoneName, Usage: 2, Selector: 0, MatchingType: 1, Data: hexSHA256("dane-ta"), TTL: 86400},
		{Name: "_443._tcp.www." + zoneName, Usage: 3, Selector: 1, MatchingType: 1, Data: hexSHA256("dane-ee"), TTL: 3600},
		// Full certificate, no hash.
		{Name: "_443._tcp.full." + zoneName, Usage: 3, Selector: 0, MatchingType: 0,
			Data: hex.EncodeToString([]byte("full-certificate-der")), TTL: 3600},
		// SHA-512.
		{Name: "_443._tcp.sha512." + zoneName, Usage: 3, Selector: 1, MatchingType: 2,
			Data: hex.EncodeToString(sha512Sum[:]), TTL: 3600},
		// Wildcard owner.
		{Name: "_443._tcp.*." + zoneName, Usage: 3, Selector: 1, MatchingType: 1, Data: hexSHA256("wildcard"), TTL: 3600},
	}
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.True(t, retrieved.Internal)
	assert.Equal(t, zone.RecordSet, retrieved.RecordSet)
	assert.Len(t, retrieved.RecordSet.TLSARecords[3].Data, 64)
	assert.Len(t, retrieved.RecordSet.TLSARecords[5].Data, 128)
}

// TestService_Save_PersistsAddedRecords adds one record of each kind, built
// with the package's record constructors, to a zone that is already saved.
func TestService_Save_PersistsAddedRecords(t *testing.T) {
	svc := newPersistenceTestService(t)
	ctx := context.Background()

	zoneName := "add-records.com."
	zone := newPersistenceTestZone(zoneName, false)
	require.NoError(t, svc.Save(ctx, zone))

	zone.AddARecord(NewARecord("@", "192.168.1.200", 3600))
	zone.AddAAAARecord(NewAAAARecord("www", "2001:db8::1", 300))
	zone.AddCNAMERecord(NewCNAMERecord("blog", "www."+zoneName, 300))
	zone.AddMXRecord(NewMXRecord("@", "mail1."+zoneName, 10, 3600))
	zone.AddMXRecord(NewMXRecord("@", "backup."+zoneName, 50, 3600))
	zone.AddNSRecord(NewNSRecord("subdomain", "ns.subdomain."+zoneName, 3600))
	zone.AddTXTRecord(NewTXTRecord("_dmarc", "v=DMARC1; p=reject", 3600))
	zone.AddSRVRecord(NewSRVRecord("_sip._udp", "sip."+zoneName, 5060, 10, 50, 3600))
	zone.AddCAARecord(NewCAARecord("@", 0, "issue", "letsencrypt.org", 3600))
	zone.AddTLSARecord(NewTLSARecord("_25._tcp.mail."+zoneName, 3, 1, 1, hexSHA256("smtp"), 3600))
	zone.AddTLSARecord(NewTLSARecord("_465._tcp.mail."+zoneName, 3, 1, 1, hexSHA256("smtps"), 3600))
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.ARecords, 3)
	assert.Len(t, retrieved.RecordSet.MXRecords, 2)
	assert.Len(t, retrieved.RecordSet.NSRecords, 3)
	assert.Len(t, retrieved.RecordSet.TLSARecords, 2)
	assert.Equal(t, zone.RecordSet, retrieved.RecordSet)
}

func TestService_Save_PersistsRemovedRecords(t *testing.T) {
	svc := newPersistenceTestService(t)
	ctx := context.Background()

	zoneName := "remove-records.com."
	zone := newPersistenceTestZone(zoneName, false)
	zone.AddNSRecord(&entities.NSRecord{Name: "subdomain", Value: "ns.subdomain." + zoneName, TTL: 3600})
	zone.AddCNAMERecord(&entities.CNAMERecord{Name: "blog", Value: "www." + zoneName, TTL: 300})
	zone.AddCNAMERecord(&entities.CNAMERecord{Name: "shop", Value: "store.example.com.", TTL: 300})
	zone.AddCAARecord(&entities.CAARecord{Name: "@", Tag: "issue", Value: "letsencrypt.org", TTL: 3600})
	zone.AddCAARecord(&entities.CAARecord{Name: "subdomain", Tag: "issue", Value: "digicert.com", TTL: 3600})
	zone.AddTLSARecord(&entities.TLSARecord{Name: "_443._tcp.www." + zoneName, Usage: 3, Selector: 1, MatchingType: 1, Data: hexSHA256("www"), TTL: 3600})
	zone.AddTLSARecord(&entities.TLSARecord{Name: "_443._tcp.api." + zoneName, Usage: 3, Selector: 1, MatchingType: 1, Data: hexSHA256("api"), TTL: 3600})
	require.NoError(t, svc.Save(ctx, zone))

	zone.RemoveARecord("www")
	zone.RemoveNSRecord("subdomain")
	zone.RemoveCNAMERecord("blog")
	zone.RemoveCAARecord("@")
	zone.RemoveTLSARecord("_443._tcp.www." + zoneName)
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	require.Len(t, retrieved.RecordSet.ARecords, 1)
	assert.Equal(t, "mail", retrieved.RecordSet.ARecords[0].Name)
	assert.Len(t, retrieved.RecordSet.NSRecords, 2)
	require.Len(t, retrieved.RecordSet.CNAMERecords, 1)
	assert.Equal(t, "shop", retrieved.RecordSet.CNAMERecords[0].Name)
	require.Len(t, retrieved.RecordSet.CAARecords, 1)
	assert.Equal(t, "subdomain", retrieved.RecordSet.CAARecords[0].Name)
	require.Len(t, retrieved.RecordSet.TLSARecords, 1)
	assert.Equal(t, "_443._tcp.api."+zoneName, retrieved.RecordSet.TLSARecords[0].Name)
}

// TestService_TLSARecordLifecycle walks a TLSA record through a certificate
// rotation: publish, publish the successor beside it, replace it with a new
// TTL, and withdraw it, reading the zone back from the datastore each time.
func TestService_TLSARecordLifecycle(t *testing.T) {
	svc := newPersistenceTestService(t)
	ctx := context.Background()

	zoneName := "lifecycle.com."
	recordName := "_443._tcp.www." + zoneName
	require.NoError(t, svc.Save(ctx, newPersistenceTestZone(zoneName, false)))

	newRecord := func(name, cert string, ttl uint32) *entities.TLSARecord {
		return &entities.TLSARecord{Name: name, Usage: 3, Selector: 1, MatchingType: 1, Data: hexSHA256(cert), TTL: ttl}
	}

	// Publish.
	require.NoError(t, svc.AddTLSARecord(ctx, zoneName, newRecord(recordName, "old-cert", 3600)))

	// Rotation: the successor is published beside the current record.
	zone, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	zone.AddTLSARecord(newRecord(recordName+"-new", "new-cert", 3600))
	require.NoError(t, svc.Save(ctx, zone))

	zone, err = svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	assert.Len(t, zone.RecordSet.TLSARecords, 2)

	// The old record is withdrawn.
	zone.RemoveTLSARecord(recordName)
	require.NoError(t, svc.Save(ctx, zone))

	zone, err = svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	require.Len(t, zone.RecordSet.TLSARecords, 1)
	assert.Equal(t, recordName+"-new", zone.RecordSet.TLSARecords[0].Name)

	// Replace with a new certificate and TTL.
	zone.RemoveTLSARecord(recordName + "-new")
	zone.AddTLSARecord(newRecord(recordName, "updated-cert", 7200))
	require.NoError(t, svc.Save(ctx, zone))

	zone, err = svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	require.Len(t, zone.RecordSet.TLSARecords, 1)
	assert.Equal(t, uint32(7200), zone.RecordSet.TLSARecords[0].TTL)
	assert.Equal(t, hexSHA256("updated-cert"), zone.RecordSet.TLSARecords[0].Data)

	// Withdraw.
	zone.RemoveTLSARecord(recordName)
	require.NoError(t, svc.Save(ctx, zone))

	zone, err = svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	assert.Empty(t, zone.RecordSet.TLSARecords)
}

func TestService_Save_KeepsZonesApart(t *testing.T) {
	svc := newPersistenceTestService(t)
	ctx := context.Background()

	zones := map[string]bool{
		"zone1.example.com.": false,
		"zone2.example.com.": false,
		"zone3.example.com.": false,
		"internal.local.":    true,
		"trusted.internal.":  true,
	}
	for name, internal := range zones {
		require.NoError(t, svc.Save(ctx, newPersistenceTestZone(name, internal)), name)
	}

	for name, internal := range zones {
		retrieved, err := svc.Zone(ctx, name)
		require.NoError(t, err, name)
		assert.Equal(t, name, retrieved.Name)
		assert.Equal(t, internal, retrieved.Internal, name)
		assert.Equal(t, "ns1."+name, retrieved.RecordSet.SOARecord.MName, name)
	}
}

func TestService_Save_ConcurrentZones(t *testing.T) {
	svc := newPersistenceTestService(t)
	ctx := context.Background()

	const workers = 10
	errs := make(chan error, 2*workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("concurrent-%d.com.", idx)
			if err := svc.Save(ctx, newPersistenceTestZone(name, idx%2 == 0)); err != nil {
				errs <- err
				return
			}
			if _, err := svc.Zone(ctx, name); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent save or get failed: %v", err)
	}
}
