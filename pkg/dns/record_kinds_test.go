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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRecordAPIService returns a service holding one empty zone, example.com.
func newRecordAPIService(t *testing.T) (*Service, *entities.Zone) {
	t.Helper()
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	zone := &entities.Zone{
		ID:       util.NewID([]byte("example.com.")),
		Name:     "example.com.",
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)
	return svc, zone
}

// Every type ResolveName serves goes through the record API: added from its
// value, found, listed, resolved back to the same value, and deleted.
func TestRecordAPI_EveryServedType(t *testing.T) {
	const tlsaData = "8cb0fc6c527506a053f4f14c8464bebbd6dede2738d11468dd953d7d6a3021f1"
	cases := []struct {
		recordType string
		name       string
		value      string
		want       interface{}
	}{
		{"A", "www.example.com.", "192.0.2.1",
			&entities.ARecord{Name: "www.example.com.", Value: "192.0.2.1", TTL: 300}},
		{"AAAA", "www.example.com.", "2001:db8::1",
			&entities.AAAARecord{Name: "www.example.com.", Value: "2001:db8::1", TTL: 300}},
		{"CNAME", "alias.example.com.", "www.example.com.",
			&entities.CNAMERecord{Name: "alias.example.com.", Value: "www.example.com.", TTL: 300}},
		{"MX", "example.com.", "mail.example.com.",
			&entities.MXRecord{Name: "example.com.", Value: "mail.example.com.", TTL: 300}},
		{"NS", "example.com.", "ns1.example.com.",
			&entities.NSRecord{Name: "example.com.", Value: "ns1.example.com.", TTL: 300}},
		{"TXT", "example.com.", "v=spf1 -all",
			&entities.TXTRecord{Name: "example.com.", Value: "v=spf1 -all", TTL: 300}},
		{"SRV", "_sip._tcp.example.com.", "10 5 5060 sip.example.com.",
			&entities.SRVRecord{Name: "_sip._tcp.example.com.", Priority: 10, Weight: 5, Port: 5060, Target: "sip.example.com.", TTL: 300}},
		{"CAA", "example.com.", `0 issue "letsencrypt.org"`,
			&entities.CAARecord{Name: "example.com.", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 300}},
		{"TLSA", "_443._tcp.www.example.com.", "3 1 1 " + tlsaData,
			&entities.TLSARecord{Name: "_443._tcp.www.example.com.", Usage: 3, Selector: 1, MatchingType: 1, Data: tlsaData, TTL: 300}},
	}

	for _, tc := range cases {
		t.Run(tc.recordType, func(t *testing.T) {
			svc, _ := newRecordAPIService(t)
			ctx := context.Background()

			require.NoError(t, svc.AddRecord(ctx, tc.name, tc.recordType, tc.value, 300))

			got, err := svc.GetRecord(ctx, tc.name, strings.ToLower(tc.recordType))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)

			listed, err := svc.ListRecords(ctx, "example.com.")
			require.NoError(t, err)
			assert.Equal(t, []interface{}{tc.want}, listed)

			values, err := svc.Resolve(ctx, tc.name, tc.recordType)
			require.NoError(t, err)
			assert.Equal(t, []string{tc.value}, values)

			require.NoError(t, svc.DeleteRecord(ctx, tc.name, tc.recordType))
			_, err = svc.GetRecord(ctx, tc.name, tc.recordType)
			assert.ErrorIs(t, err, ErrRecordNotFound)
		})
	}
}

// A structured value that does not parse is refused and nothing is stored.
func TestAddRecord_InvalidStructuredValue(t *testing.T) {
	cases := []struct {
		recordType string
		value      string
	}{
		{"SRV", "sip.example.com."},
		{"SRV", "10 5 notaport sip.example.com."},
		{"CAA", "   "},
		{"TLSA", "three 1 1 abcd"},
	}

	for _, tc := range cases {
		t.Run(tc.recordType+"/"+tc.value, func(t *testing.T) {
			svc, zone := newRecordAPIService(t)

			err := svc.AddRecord(context.Background(), "x.example.com.", tc.recordType, tc.value, 300)
			require.ErrorIs(t, err, ErrInvalidRecordValue)
			var recordErr *RecordError
			require.ErrorAs(t, err, &recordErr)
			assert.Equal(t, "add", recordErr.Op)

			assert.Equal(t, entities.RecordSet{}, zone.RecordSet)
		})
	}
}

// SOA belongs to the zone and the DNSSEC types to signing: the record API
// refuses them like any type it does not manage.
func TestRecordAPI_ZoneManagedTypesRefused(t *testing.T) {
	for _, recordType := range []string{"SOA", "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "PTR"} {
		t.Run(recordType, func(t *testing.T) {
			svc, zone := newRecordAPIService(t)
			ctx := context.Background()

			err := svc.AddRecord(ctx, "example.com.", recordType, "x", 300)
			assert.ErrorIs(t, err, ErrRecordTypeNotSupported)
			assert.ErrorIs(t, svc.DeleteRecord(ctx, "example.com.", recordType), ErrRecordTypeNotSupported)
			_, err = svc.GetRecord(ctx, "example.com.", recordType)
			assert.ErrorIs(t, err, ErrRecordTypeNotSupported)
			assert.Equal(t, entities.RecordSet{}, zone.RecordSet)
		})
	}
}
