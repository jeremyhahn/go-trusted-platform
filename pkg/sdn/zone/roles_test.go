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

package zone_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestZoneForRole_Defaults resolves both lifecycle roles to their built-in
// holders.
func TestZoneForRole_Defaults(t *testing.T) {
	got, err := zone.ZoneForRole(zone.Defaults(), zone.LifecycleRoleProvisioning)
	require.NoError(t, err)
	assert.Equal(t, zone.ZoneProvisioning, got)

	got, err = zone.ZoneForRole(zone.Defaults(), zone.LifecycleRoleQuarantine)
	require.NoError(t, err)
	assert.Equal(t, zone.ZoneQuarantine, got)
}

// TestZoneForRole_NotFound returns ErrNoZoneForRole when no zone holds the
// role.
func TestZoneForRole_NotFound(t *testing.T) {
	_, err := zone.ZoneForRole([]zone.ZoneConfig{{Name: "lab"}}, zone.LifecycleRoleQuarantine)
	var target zone.ErrNoZoneForRole
	require.True(t, errors.As(err, &target), "got %v", err)
	assert.Equal(t, zone.LifecycleRoleQuarantine, target.Role)
}
