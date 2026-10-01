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

package pxe

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// Environment-4 reference VLANs used across the pxe tests.
const (
	testQuarantineVLAN   uint16 = 404
	testProvisioningVLAN uint16 = 405
	testControlPlaneVLAN uint16 = 406
)

// testNetPlan is the environment-4 reference plan with the built-in zones.
var testNetPlan = mustPlan()

func mustPlan() *netplan.Plan {
	p, err := netplan.New(netplan.Environment{ID: 4}, zone.Defaults())
	if err != nil {
		panic(err)
	}
	return p
}

// testServiceConfig returns NewServiceConfig for the reference plan.
func testServiceConfig() *ServiceConfig {
	cfg, err := NewServiceConfig(testNetPlan)
	if err != nil {
		panic(err)
	}
	return cfg
}
