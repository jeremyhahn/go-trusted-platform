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
	"errors"
	"sort"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/mocks"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// addResolveTestZones stores example.com. and the nested sub.example.com.
// for tenant-1. example.com. also holds "host.sub", which the nested zone
// shadows.
func addResolveTestZones(dao *mocks.MockZoneDAO) {
	for _, zone := range []*entities.Zone{
		{
			Name:     "example.com.",
			TenantID: "tenant-1",
			RecordSet: entities.RecordSet{
				ARecords: []*entities.ARecord{
					{Name: "@", Value: "10.0.0.1"},
					{Name: "www", Value: "10.0.0.2"},
					{Name: "host.sub", Value: "10.0.0.99"},
				},
				AAAARecords: []*entities.AAAARecord{{Name: "www", Value: "fd00::2"}},
				TXTRecords:  []*entities.TXTRecord{{Name: "www.example.com", Value: "absolute-no-dot"}},
				MXRecords:   []*entities.MXRecord{{Name: "example.com.", Value: "mail.example.com."}},
			},
		},
		{
			Name:     "sub.example.com.",
			TenantID: "tenant-1",
			RecordSet: entities.RecordSet{
				ARecords: []*entities.ARecord{
					{Name: "", Value: "10.0.1.1"},
					{Name: "host", Value: "10.0.1.2"},
				},
			},
		},
	} {
		zone.ID = util.NewID([]byte(zone.Name))
		dao.AddZone(zone)
	}
}

// answerValues flattens a resolution's records to sorted "TYPE value" lines.
func answerValues(rs *entities.RecordSet) []string {
	values := []string{}
	for _, r := range rs.ARecords {
		values = append(values, "A "+r.Value)
	}
	for _, r := range rs.AAAARecords {
		values = append(values, "AAAA "+r.Value)
	}
	for _, r := range rs.MXRecords {
		values = append(values, "MX "+r.Value)
	}
	for _, r := range rs.TXTRecords {
		values = append(values, "TXT "+r.Value)
	}
	sort.Strings(values)
	return values
}

// TestResolveName_AnswersOnlyTheQueriedOwner pins API resolution
// (docs/dns/resolution.md, "API resolve"): the longest managed zone suffix
// answers, only the queried owner's records come back, and the type filters.
func TestResolveName_AnswersOnlyTheQueriedOwner(t *testing.T) {
	svc, dao := createServiceWithMockDAO(t, "tenant-1")
	addResolveTestZones(dao)

	cases := []struct {
		name          string
		qname         string
		recordType    string
		wantZone      string
		authoritative bool
		want          []string
	}{
		{"OwnerInsideZone", "www.example.com.", "A", "example.com.", true, []string{"A 10.0.0.2"}},
		{"OwnerEveryType", "www.example.com.", "", "example.com.", true,
			[]string{"A 10.0.0.2", "AAAA fd00::2", "TXT absolute-no-dot"}},
		{"ApexOnlyApexRecords", "example.com.", "", "example.com.", true,
			[]string{"A 10.0.0.1", "MX mail.example.com."}},
		{"TypeFilter", "www.example.com.", "AAAA", "example.com.", true, []string{"AAAA fd00::2"}},
		{"UnknownOwnerInsideZone", "nope.example.com.", "A", "example.com.", true, []string{}},
		{"OutsideEveryZone", "www.example.org.", "A", "", false, []string{}},
		{"CaseAndNoTrailingDot", "WWW.Example.COM", "a", "example.com.", true, []string{"A 10.0.0.2"}},
		{"NestedZoneLongestMatch", "host.sub.example.com.", "A", "sub.example.com.", true, []string{"A 10.0.1.2"}},
		{"NestedZoneApex", "SUB.example.com", "A", "sub.example.com.", true, []string{"A 10.0.1.1"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolution, err := ResolveName(context.Background(), svc, tc.qname, tc.recordType)
			require.NoError(t, err)
			assert.Equal(t, tc.wantZone, resolution.Zone)
			assert.Equal(t, tc.authoritative, resolution.Authoritative)
			assert.Equal(t, tc.want, answerValues(&resolution.Records))
		})
	}
}

// TestResolveName_ZoneTheCallerMayNotReadIsNotAnswered: another tenant's
// nested zone owns the name, so neither it nor the caller's parent zone —
// which still holds a shadowed record for the name — answers.
func TestResolveName_ZoneTheCallerMayNotReadIsNotAnswered(t *testing.T) {
	svc, dao := createServiceWithMockDAO(t, "tenant-1")
	addResolveTestZones(dao)
	nested, err := dao.Get(context.Background(), util.NewID([]byte("sub.example.com.")))
	require.NoError(t, err)
	nested.TenantID = "tenant-2"

	resolution, err := ResolveName(context.Background(), svc, "host.sub.example.com.", "A")
	require.NoError(t, err)
	assert.False(t, resolution.Authoritative)
	assert.Empty(t, resolution.Zone)
	assert.Empty(t, answerValues(&resolution.Records))
}

// TestResolveName_UnservedRecordTypeRefused: a type resolution does not
// answer is ErrRecordTypeNotSupported, named in the message.
func TestResolveName_UnservedRecordTypeRefused(t *testing.T) {
	svc, dao := createServiceWithMockDAO(t, "tenant-1")
	addResolveTestZones(dao)

	for _, recordType := range []string{"SOA", "BOGUS"} {
		t.Run(recordType, func(t *testing.T) {
			resolution, err := ResolveName(context.Background(), svc, "www.example.com.", recordType)
			require.Nil(t, resolution)
			require.True(t, errors.Is(err, ErrRecordTypeNotSupported), "err = %v", err)
			assert.Contains(t, err.Error(), recordType)
		})
	}
}

// TestService_Resolve_AnswersOnlyTheQueriedOwner: the []string Resolve that
// MCP, QUIC and the legacy REST handler call answers through ResolveName.
func TestService_Resolve_AnswersOnlyTheQueriedOwner(t *testing.T) {
	svc, dao := createServiceWithMockDAO(t, "tenant-1")
	addResolveTestZones(dao)

	apex, err := svc.Resolve(context.Background(), "Example.com", "A")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1"}, apex)

	nested, err := svc.Resolve(context.Background(), "host.sub.example.com.", "A")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.1.2"}, nested)

	_, err = svc.Resolve(context.Background(), "www.example.org.", "A")
	assert.ErrorIs(t, err, ErrRecordNotFound)
}
