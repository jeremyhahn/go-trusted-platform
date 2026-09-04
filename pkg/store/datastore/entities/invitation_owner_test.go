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

package entities

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewInvitation_IsNotAnOwnershipGrant is the default that matters. Every
// existing call site uses this constructor, and none of them should confer
// tenant ownership (#158).
func TestNewInvitation_IsNotAnOwnershipGrant(t *testing.T) {
	inv, err := NewInvitation("tenant-a", "member@example.test", "admin", 1, time.Hour)
	require.NoError(t, err)

	assert.False(t, inv.InitialAdmin,
		"an ordinary invitation conferred tenant ownership")
}

// TestNewInvitation_AnAdminRoleIsNotOwnership pins the distinction the field
// exists for. A tenant's later administrators hold the admin role and do not
// own the tenant; conflating the two would make every admin invitation an
// ownership grant.
func TestNewInvitation_AnAdminRoleIsNotOwnership(t *testing.T) {
	inv, err := NewInvitation("tenant-a", "second-admin@example.test", "admin", 1, time.Hour)
	require.NoError(t, err)

	assert.Equal(t, "admin", inv.Role)
	assert.False(t, inv.InitialAdmin)
}

// TestNewInitialAdminInvitation_ConfersOwnership is the positive case.
func TestNewInitialAdminInvitation_ConfersOwnership(t *testing.T) {
	inv, err := NewInitialAdminInvitation("tenant-a", "owner@example.test", "admin", 1, time.Hour)
	require.NoError(t, err)

	assert.True(t, inv.InitialAdmin)
	assert.Equal(t, "tenant-a", inv.TenantID)
	assert.Equal(t, InvitationStatusPending, inv.Status)
}

// TestInvitation_InitialAdminSurvivesARoundTrip proves the marker persists.
// The redemption path reads it back from storage, so a field that serialised
// out and not back in would silently make every owner invitation an ordinary
// one — failing safe, but failing.
func TestInvitation_InitialAdminSurvivesARoundTrip(t *testing.T) {
	inv, err := NewInitialAdminInvitation("tenant-a", "owner@example.test", "admin", 1, time.Hour)
	require.NoError(t, err)

	encoded, err := json.Marshal(inv)
	require.NoError(t, err)

	var decoded Invitation
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	assert.True(t, decoded.InitialAdmin,
		"the initial-admin marker did not survive serialisation")
}

// TestInvitation_OrdinaryInvitationsOmitTheMarker keeps the wire shape of the
// common case unchanged: the field is `omitempty`, so existing consumers of
// the invitation JSON see exactly what they saw before.
func TestInvitation_OrdinaryInvitationsOmitTheMarker(t *testing.T) {
	inv, err := NewInvitation("tenant-a", "member@example.test", "member", 1, time.Hour)
	require.NoError(t, err)

	encoded, err := json.Marshal(inv)
	require.NoError(t, err)

	assert.NotContains(t, string(encoded), "initial_admin",
		"an ordinary invitation now carries a field its consumers did not have before")
}
