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

package device

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// planStaleSharedVLANProfile writes a profile with a shared provisioning and
// trusted VLAN straight through the DAO, bypassing the service layer.
//
// The service layer will not create such a profile, so this is the only way
// to produce the shape the assignment paths actually have to cope with: a
// profile stored before the distinctness rule existed, or written by a
// component holding the DAO directly.
func plantStaleSharedVLANProfile(t *testing.T, ds *Datastore, id uint64, vlan uint16) *entities.DeviceProfile {
	t.Helper()

	profileDAO, err := ds.ProfileDAO()
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:   id,
		Name: "StaleSharedVLAN",
		Role: entities.DeviceRoleServer,
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork:     {VLAN: vlan},
			entities.DefaultPostEnrollmentNetwork: {VLAN: vlan},
		},
	}
	require.NoError(t, profileDAO.Save(context.Background(), profile))
	return profile
}

// TestProfileService_AssignRunsTheVLANValidation closes the assignment half
// of the gap #133 reports: AssignToDeviceWithEK reached profileDAO.Save
// directly, so it did not run validateNetworkPhases.
//
// It does not touch the network config — it writes back a profile it only
// loaded — which is precisely why the gap was invisible: an invalid profile
// was silently re-persisted by an operation that never inspected its
// networks. Binding one to real hardware is the direction that must be
// refused.
func TestProfileService_AssignRunsTheVLANValidation(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	stale := plantStaleSharedVLANProfile(t, ds, 11, 300)

	var notDistinct ErrProfileVLANsNotDistinct

	err = service.AssignToDeviceWithEK(ctx, stale.ID, "EK-STALE", "aa:bb:cc:dd:ee:ff", "")
	require.ErrorAs(t, err, &notDistinct)
	assert.Equal(t, uint16(300), notDistinct.VLAN)

	// AssignToDevice is the back-compatible wrapper and must not be a way
	// around the same check.
	err = service.AssignToDevice(ctx, stale.ID, "EK-STALE", "aa:bb:cc:dd:ee:ff")
	require.ErrorAs(t, err, &notDistinct)

	// The refused assignment left no trace on the stored profile.
	stored, err := service.Get(ctx, stale.ID)
	require.NoError(t, err)
	assert.False(t, stored.Assigned)
	assert.Empty(t, stored.EKSerial)
}

// TestProfileService_UnassignDoesNotValidate is the deliberate asymmetry.
//
// Validation guards the INTRODUCTION of invalid state; unassign is the
// REMOVAL path. A device carrying a profile whose VLANs are already invalid
// must still be detachable from it — otherwise the operator cannot stop
// using a bad profile until they first repair it, which is the wrong
// constraint during an incident. Delete does not validate either, so
// refusing here would protect an inconsistency in which paths validate
// rather than an invariant.
//
// This test exists to stop someone restoring "consistency" by routing
// unassign through saveValidated.
func TestProfileService_UnassignDoesNotValidate(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	stale := plantStaleSharedVLANProfile(t, ds, 13, 300)

	// Bind the stale profile through the DAO, since the service layer
	// refuses to assign it — this is the state an operator is stuck in.
	profileDAO, err := ds.ProfileDAO()
	require.NoError(t, err)
	stale.EKSerial = "EK-STUCK"
	stale.MACAddress = "aa:bb:cc:dd:ee:ff"
	stale.Assigned = true
	require.NoError(t, profileDAO.Save(ctx, stale))

	// The safety valve: unassign succeeds despite the invalid VLANs.
	require.NoError(t, service.UnassignFromDevice(ctx, stale.ID),
		"unassign must not be blocked by a profile's pre-existing invalid VLANs")

	// And it actually removed the binding rather than reporting success
	// without doing anything.
	stored, err := service.Get(ctx, stale.ID)
	require.NoError(t, err)
	assert.False(t, stored.Assigned)
	assert.Empty(t, stored.EKSerial)
	assert.Empty(t, stored.MACAddress)
	assert.Empty(t, stored.EKCert)
}

// TestProfileService_AssignUnassignValidProfile is the happy half: a profile
// with distinct VLANs assigns and unassigns normally, so the new validation
// does not break the ordinary path.
func TestProfileService_AssignUnassignValidProfile(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:   12,
		Name: "DistinctVLANs",
		Role: entities.DeviceRoleServer,
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork:     {VLAN: 100},
			entities.DefaultPostEnrollmentNetwork: {VLAN: 200},
		},
	}
	require.NoError(t, service.Save(ctx, profile))

	require.NoError(t, service.AssignToDeviceWithEK(ctx, profile.ID, "EK-OK", "aa:bb:cc:00:11:22", ""))

	assigned, err := service.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.True(t, assigned.Assigned)
	assert.Equal(t, "EK-OK", assigned.EKSerial)
	assert.Equal(t, "aa:bb:cc:00:11:22", assigned.MACAddress)

	require.NoError(t, service.UnassignFromDevice(ctx, profile.ID))

	unassigned, err := service.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.False(t, unassigned.Assigned)
	assert.Empty(t, unassigned.EKSerial)
	assert.Empty(t, unassigned.MACAddress)
}
