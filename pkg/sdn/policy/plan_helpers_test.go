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

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// Environment-4 reference VLANs used across the policy tests.
const (
	testQuarantineVLAN   uint16 = 404
	testProvisioningVLAN uint16 = 405
	testControlPlaneVLAN uint16 = 406
	testStorageVLAN      uint16 = 407
	testManagementVLAN   uint16 = 402
)

// testPlan returns the reference plan of environment 4 with the built-in
// zones.
func testPlan(t *testing.T) *netplan.Plan {
	t.Helper()
	p, err := netplan.New(netplan.Environment{ID: 4}, zone.Defaults())
	require.NoError(t, err)
	return p
}
