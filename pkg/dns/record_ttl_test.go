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
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/mocks"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAddRecord_DefaultTTL: a record added with no TTL (0) takes the
// configured default-ttl; an explicit TTL is kept.
func TestAddRecord_DefaultTTL(t *testing.T) {
	svc, zone := newRecordAPIService(t)
	svc.params.Config.DefaultTTL = 120
	ctx := context.Background()

	require.NoError(t, svc.AddRecord(ctx, "a.example.com.", "A", "192.0.2.1", 0))
	require.NoError(t, svc.AddRecord(ctx, "b.example.com.", "A", "192.0.2.2", 300))

	require.Len(t, zone.RecordSet.ARecords, 2)
	assert.Equal(t, uint32(120), zone.RecordSet.ARecords[0].TTL)
	assert.Equal(t, uint32(300), zone.RecordSet.ARecords[1].TTL)
}

// TestAddRecord_InvalidTTL: a TTL outside RFC 2181 §8's range is refused
// before the zone is touched.
func TestAddRecord_InvalidTTL(t *testing.T) {
	for _, ttl := range []int{-1, maxTTL + 1} {
		svc, zone := newRecordAPIService(t)

		err := svc.AddRecord(context.Background(), "a.example.com.", "A", "192.0.2.1", ttl)
		require.ErrorIs(t, err, ErrInvalidTTL, ttl)
		var recordErr *RecordError
		require.ErrorAs(t, err, &recordErr)
		assert.Equal(t, "add", recordErr.Op)
		assert.Equal(t, entities.RecordSet{}, zone.RecordSet)
	}
}

// TestCreateZone_DefaultTTL: a zone created through the API takes the
// configured default-ttl, and the fallback when none is configured.
func TestCreateZone_DefaultTTL(t *testing.T) {
	cases := map[string]struct {
		defaultTTL int
		want       uint32
	}{
		"configured":     {defaultTTL: 60, want: 60},
		"not configured": {defaultTTL: 0, want: fallbackRecordTTL},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mockDAO := mocks.NewMockZoneDAO()
			var saved *entities.Zone
			mockDAO.SaveFunc = func(_ context.Context, zone *entities.Zone) error {
				saved = zone
				return nil
			}
			svc := &Service{
				params:  &Params{TenantID: "tenant-1", Config: &Config{DefaultTTL: tc.defaultTTL}},
				zoneDAO: mockDAO,
			}

			require.NoError(t, svc.CreateZone(context.Background(), "newzone.com."))
			require.NotNil(t, saved)
			assert.Equal(t, tc.want, saved.TTL)
		})
	}
}

// TestRegisterWithNetworkZone_DefaultTTL: a device's sub-zone A record takes
// the configured default-ttl.
func TestRegisterWithNetworkZone_DefaultTTL(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	svc.params.Config.DefaultTTL = 90
	svc.params.Config.ZoneSubdomains = true
	svc.params.Config.InternalServer = &InternalServer{Zone: entities.Zone{Name: "example.internal."}}

	subZone := &entities.Zone{
		ID:       util.NewID([]byte("lab.example.internal.")),
		Name:     "lab.example.internal.",
		TenantID: "tenant-1",
	}
	mockDAO.AddZone(subZone)

	require.NoError(t, svc.RegisterWithNetworkZone(context.Background(), "node1", "lab", "10.0.0.5"))

	require.Len(t, subZone.RecordSet.ARecords, 1)
	assert.Equal(t, uint32(90), subZone.RecordSet.ARecords[0].TTL)
}
