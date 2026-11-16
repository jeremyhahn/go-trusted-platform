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

// TestInitNetworkZoneSubdomains_Disabled verifies that when ZoneSubdomains is
// false the function is a no-op and returns nil.
func TestInitNetworkZoneSubdomains_Disabled(t *testing.T) {
	cfg := &Config{ZoneSubdomains: false}
	err := InitNetworkZoneSubdomains(
		context.Background(), cfg, []string{"control-plane", "public"}, nil, "platform",
	)
	assert.NoError(t, err, "disabled zone-subdomains must be a no-op")
}

// TestInitNetworkZoneSubdomains_NoInternalServer returns the typed error when
// zone_subdomains is enabled but no internal server is configured.
func TestInitNetworkZoneSubdomains_NoInternalServer(t *testing.T) {
	cfg := &Config{
		ZoneSubdomains: true,
		// InternalServer intentionally nil
	}
	err := InitNetworkZoneSubdomains(
		context.Background(), cfg, []string{"control-plane"}, mocks.NewMockZoneDAO(), "platform",
	)
	var target ErrZoneSubdomainsNoInternalServer
	assert.ErrorAs(t, err, &target)
}

// TestInitNetworkZoneSubdomains_NoNetworkZones returns the typed error when no
// network zones are provided but zone_subdomains is enabled.
func TestInitNetworkZoneSubdomains_NoNetworkZones(t *testing.T) {
	cfg := &Config{
		ZoneSubdomains: true,
		InternalServer: &InternalServer{
			Zone: entities.Zone{Name: "example.internal."},
		},
	}
	err := InitNetworkZoneSubdomains(
		context.Background(), cfg, nil, mocks.NewMockZoneDAO(), "platform",
	)
	var target ErrZoneSubdomainsNoNetworkZones
	assert.ErrorAs(t, err, &target)
}

// TestInitNetworkZoneSubdomains_CreatesBuiltinZones verifies that sub-zones are
// created for all provided network zone names under the internal domain.
func TestInitNetworkZoneSubdomains_CreatesBuiltinZones(t *testing.T) {
	zDAO := mocks.NewMockZoneDAO()
	cfg := &Config{
		ZoneSubdomains: true,
		InternalServer: &InternalServer{
			Zone: entities.Zone{
				Name:     "example.internal.",
				TenantID: "platform",
			},
		},
	}
	networkZones := []string{"control-plane", "public", "provisioning", "quarantine", "storage", "tenant", "management"}

	err := InitNetworkZoneSubdomains(
		context.Background(), cfg, networkZones, zDAO, "platform",
	)
	require.NoError(t, err)

	// Verify each sub-zone was persisted in the DAO.
	for _, z := range networkZones {
		subZoneName := z + ".example.internal."
		id := util.NewID([]byte(subZoneName))
		zone, err := zDAO.Get(context.Background(), id)
		require.NoError(t, err, "sub-zone %s must exist", subZoneName)
		assert.Equal(t, subZoneName, zone.Name)
		assert.True(t, zone.Internal, "sub-zone must be marked internal")
		assert.Equal(t, "platform", zone.TenantID)
		require.NotNil(t, zone.RecordSet.SOARecord)
		assert.Equal(t, "ns1.example.internal.", zone.RecordSet.SOARecord.MName)
		require.Len(t, zone.RecordSet.NSRecords, 1)
	}
}

// TestInitNetworkZoneSubdomains_Idempotent verifies that calling
// InitNetworkZoneSubdomains twice does not overwrite existing zones.
func TestInitNetworkZoneSubdomains_Idempotent(t *testing.T) {
	zDAO := mocks.NewMockZoneDAO()
	cfg := &Config{
		ZoneSubdomains: true,
		InternalServer: &InternalServer{
			Zone: entities.Zone{Name: "example.internal."},
		},
	}

	// First call creates the zones.
	err := InitNetworkZoneSubdomains(
		context.Background(), cfg, []string{"control-plane"}, zDAO, "platform",
	)
	require.NoError(t, err)

	id := util.NewID([]byte("control-plane.example.internal."))
	first, err := zDAO.Get(context.Background(), id)
	require.NoError(t, err)

	// Second call must not fail and must not alter the existing zone.
	err = InitNetworkZoneSubdomains(
		context.Background(), cfg, []string{"control-plane"}, zDAO, "platform",
	)
	require.NoError(t, err)

	second, err := zDAO.Get(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, first, second, "idempotent call must not alter existing zone")
}

// TestInitNetworkZoneSubdomains_CustomZone verifies that a custom (non-builtin)
// zone name produces the correct sub-zone.
func TestInitNetworkZoneSubdomains_CustomZone(t *testing.T) {
	zDAO := mocks.NewMockZoneDAO()
	cfg := &Config{
		ZoneSubdomains: true,
		InternalServer: &InternalServer{
			Zone: entities.Zone{Name: "corp.internal."},
		},
	}

	err := InitNetworkZoneSubdomains(
		context.Background(), cfg, []string{"dmz"}, zDAO, "platform",
	)
	require.NoError(t, err)

	subZoneName := "dmz.corp.internal."
	id := util.NewID([]byte(subZoneName))
	zone, err := zDAO.Get(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, subZoneName, zone.Name)
}

// TestService_RegisterWithNetworkZone_CreatesRecord verifies that when
// zone_subdomains is enabled and the sub-zone exists, a zone-qualified A record
// is created for the host.
func TestService_RegisterWithNetworkZone_CreatesRecord(t *testing.T) {
	ds := createTestDatastore(t)
	cfg := &Config{
		ZoneSubdomains: true,
		InternalServer: &InternalServer{
			Zone: entities.Zone{
				Name:     "example.internal.",
				TenantID: "platform",
			},
		},
	}
	svc, err := NewService(&Params{
		TenantID:  "platform",
		Config:    cfg,
		Datastore: ds,
	})
	require.NoError(t, err)

	// Pre-create the sub-zone as the plugin would at startup.
	subZoneName := "control-plane.example.internal."
	zoneDAO, err := ds.ZoneDAO()
	require.NoError(t, err)
	subZone := &entities.Zone{
		ID:       util.NewID([]byte(subZoneName)),
		Name:     subZoneName,
		TenantID: "platform",
		TTL:      3600,
		Internal: true,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:  subZoneName,
				MName: "ns1.example.internal.",
				RName: "hostmaster.example.internal.",
			},
		},
	}
	err = zoneDAO.Save(context.Background(), subZone)
	require.NoError(t, err)

	// Register the host under the control-plane network zone.
	err = svc.RegisterWithNetworkZone(context.Background(), "node-01", "control-plane", "10.0.0.1")
	require.NoError(t, err)

	// Verify A record was added to the sub-zone.
	saved, err := zoneDAO.Get(context.Background(), util.NewID([]byte(subZoneName)))
	require.NoError(t, err)
	found := false
	for _, r := range saved.RecordSet.ARecords {
		if r.Name == "node-01" && r.Value == "10.0.0.1" {
			found = true
			break
		}
	}
	assert.True(t, found, "A record node-01->10.0.0.1 must be present in control-plane.example.internal.")
}

// TestService_RegisterWithNetworkZone_Disabled verifies that no record is
// created when zone_subdomains is false.
func TestService_RegisterWithNetworkZone_Disabled(t *testing.T) {
	ds := createTestDatastore(t)
	cfg := &Config{
		ZoneSubdomains: false,
		InternalServer: &InternalServer{
			Zone: entities.Zone{Name: "example.internal."},
		},
	}
	svc, err := NewService(&Params{
		TenantID:  "platform",
		Config:    cfg,
		Datastore: ds,
	})
	require.NoError(t, err)

	// Should be a no-op; no sub-zone created.
	err = svc.RegisterWithNetworkZone(context.Background(), "node-01", "control-plane", "10.0.0.1")
	assert.NoError(t, err)

	// Confirm the sub-zone was never written.
	zoneDAO, err := ds.ZoneDAO()
	require.NoError(t, err)
	id := util.NewID([]byte("control-plane.example.internal."))
	_, err = zoneDAO.Get(context.Background(), id)
	assert.Error(t, err, "sub-zone must not exist when zone_subdomains is false")
}

// TestService_RegisterWithNetworkZone_EmptyNetworkZone verifies that an empty
// network zone name is a no-op.
func TestService_RegisterWithNetworkZone_EmptyNetworkZone(t *testing.T) {
	ds := createTestDatastore(t)
	cfg := &Config{
		ZoneSubdomains: true,
		InternalServer: &InternalServer{
			Zone: entities.Zone{Name: "example.internal."},
		},
	}
	svc, err := NewService(&Params{
		TenantID:  "platform",
		Config:    cfg,
		Datastore: ds,
	})
	require.NoError(t, err)

	err = svc.RegisterWithNetworkZone(context.Background(), "node-01", "", "10.0.0.1")
	assert.NoError(t, err)
}

// TestService_RegisterWithNetworkZone_BMCNameSkipped verifies that BMC names
// (ending in "-bmc") are never zone-qualified.
func TestService_RegisterWithNetworkZone_BMCNameSkipped(t *testing.T) {
	ds := createTestDatastore(t)
	cfg := &Config{
		ZoneSubdomains: true,
		InternalServer: &InternalServer{
			Zone: entities.Zone{
				Name:     "example.internal.",
				TenantID: "platform",
			},
		},
	}
	svc, err := NewService(&Params{
		TenantID:  "platform",
		Config:    cfg,
		Datastore: ds,
	})
	require.NoError(t, err)

	// Pre-create the sub-zone to confirm the BMC guard fires before any DAO call.
	subZoneName := "management.example.internal."
	zoneDAO, err := ds.ZoneDAO()
	require.NoError(t, err)
	subZone := &entities.Zone{
		ID:       util.NewID([]byte(subZoneName)),
		Name:     subZoneName,
		TenantID: "platform",
		TTL:      3600,
		Internal: true,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:  subZoneName,
				MName: "ns1.example.internal.",
				RName: "hostmaster.example.internal.",
			},
		},
	}
	err = zoneDAO.Save(context.Background(), subZone)
	require.NoError(t, err)

	err = svc.RegisterWithNetworkZone(context.Background(), "node-01-bmc", "management", "10.0.0.5")
	assert.NoError(t, err)

	// Confirm no A record was written for the BMC alias.
	saved, err := zoneDAO.Get(context.Background(), util.NewID([]byte(subZoneName)))
	require.NoError(t, err)
	for _, r := range saved.RecordSet.ARecords {
		assert.NotEqual(t, "node-01-bmc", r.Name, "BMC name must never be zone-qualified")
	}
}

// TestService_RegisterWithNetworkZone_Idempotent verifies that registering the
// same host+zone+ip twice does not create duplicate A records.
func TestService_RegisterWithNetworkZone_Idempotent(t *testing.T) {
	ds := createTestDatastore(t)
	cfg := &Config{
		ZoneSubdomains: true,
		InternalServer: &InternalServer{
			Zone: entities.Zone{
				Name:     "example.internal.",
				TenantID: "platform",
			},
		},
	}
	svc, err := NewService(&Params{
		TenantID:  "platform",
		Config:    cfg,
		Datastore: ds,
	})
	require.NoError(t, err)

	subZoneName := "control-plane.example.internal."
	zoneDAO, err := ds.ZoneDAO()
	require.NoError(t, err)
	subZone := &entities.Zone{
		ID:       util.NewID([]byte(subZoneName)),
		Name:     subZoneName,
		TenantID: "platform",
		TTL:      3600,
		Internal: true,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:  subZoneName,
				MName: "ns1.example.internal.",
				RName: "hostmaster.example.internal.",
			},
		},
	}
	err = zoneDAO.Save(context.Background(), subZone)
	require.NoError(t, err)

	require.NoError(t, svc.RegisterWithNetworkZone(context.Background(), "node-01", "control-plane", "10.0.0.1"))
	require.NoError(t, svc.RegisterWithNetworkZone(context.Background(), "node-01", "control-plane", "10.0.0.1"))

	saved, err := zoneDAO.Get(context.Background(), util.NewID([]byte(subZoneName)))
	require.NoError(t, err)
	count := 0
	for _, r := range saved.RecordSet.ARecords {
		if r.Name == "node-01" && r.Value == "10.0.0.1" {
			count++
		}
	}
	assert.Equal(t, 1, count, "duplicate registration must be de-duped")
}

// TestService_RegisterWithNetworkZone_GetFails: a sub-zone that is absent is
// skipped, but any other failure reading it is returned, not swallowed.
func TestService_RegisterWithNetworkZone_GetFails(t *testing.T) {
	cases := map[string]struct {
		getErr  error
		wantErr error
	}{
		"not found":   {getErr: mocks.ErrZoneNotFound},
		"read failed": {getErr: mocks.ErrMockGet, wantErr: mocks.ErrMockGet},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mockDAO := mocks.NewMockZoneDAO()
			mockDAO.GetFunc = func(context.Context, uint64) (*entities.Zone, error) {
				return nil, tc.getErr
			}
			svc := &Service{
				params: &Params{TenantID: "platform", Config: &Config{
					ZoneSubdomains: true,
					InternalServer: &InternalServer{Zone: entities.Zone{Name: "example.internal."}},
				}},
				zoneDAO: mockDAO,
			}

			err := svc.RegisterWithNetworkZone(context.Background(), "node-01", "control-plane", "10.0.0.1")
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
			var zoneErr *ZoneError
			require.ErrorAs(t, err, &zoneErr)
			assert.Equal(t, "control-plane.example.internal.", zoneErr.Zone)
		})
	}
}

// TestIsBMCName validates the helper.
func TestIsBMCName(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"node-01-bmc", true},
		{"gw-bmc", true},
		{"node-01", false},
		{"bmc-only", false},
		{"bmc", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			assert.Equal(t, tc.want, IsBMCName(tc.host))
		})
	}
}

// TestNetworkZoneSubdomainFQDN verifies the helper constructs the correct FQDN.
func TestNetworkZoneSubdomainFQDN(t *testing.T) {
	fqdn := NetworkZoneSubdomainFQDN("node-01", "control-plane", "example.internal")
	assert.Equal(t, "node-01.control-plane.example.internal", fqdn)
}

// TestErrZoneSubdomainsNoInternalServer_Error checks the typed error message.
func TestErrZoneSubdomainsNoInternalServer_Error(t *testing.T) {
	err := ErrZoneSubdomainsNoInternalServer{}
	assert.Contains(t, err.Error(), "internal DNS server")
}

// TestErrZoneSubdomainsNoNetworkZones_Error checks the typed error message.
func TestErrZoneSubdomainsNoNetworkZones_Error(t *testing.T) {
	err := ErrZoneSubdomainsNoNetworkZones{}
	assert.Contains(t, err.Error(), "network zones")
}

// TestInitNetworkZoneSubdomains_SaveError verifies that a DAO save error
// propagates correctly.
func TestInitNetworkZoneSubdomains_SaveError(t *testing.T) {
	zDAO := mocks.NewMockZoneDAO()
	zDAO.SaveFunc = func(_ context.Context, _ *entities.Zone) error {
		return mocks.ErrMockSave
	}
	cfg := &Config{
		ZoneSubdomains: true,
		InternalServer: &InternalServer{
			Zone: entities.Zone{Name: "example.internal."},
		},
	}
	err := InitNetworkZoneSubdomains(
		context.Background(), cfg, []string{"control-plane"}, zDAO, "platform",
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "control-plane.example.internal.")
}
