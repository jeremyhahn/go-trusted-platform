//go:build !fips

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

package vpn

import (
	"testing"

	"github.com/stretchr/testify/assert"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vpn/agent"
)

func TestClientDataPlanes_WireGuardAlwaysMASQUEOnlyWhenHeld(t *testing.T) {
	device := unopenedDevice{err: &agent.ErrNoDevice{Reason: "not opened"}}

	assert.Equal(t, []gwvpn.DataPlaneKind{gwvpn.DataPlaneWireGuard}, planeKinds(clientDataPlanes(nil, device, false)))
	assert.Equal(t, []gwvpn.DataPlaneKind{gwvpn.DataPlaneWireGuard, gwvpn.DataPlaneMASQUE}, planeKinds(clientDataPlanes(nil, device, true)))
}

func TestKernelDataPlanes_IsWireGuard(t *testing.T) {
	assert.Equal(t, []gwvpn.DataPlaneKind{gwvpn.DataPlaneWireGuard}, planeKinds(kernelDataPlanes()))
}
