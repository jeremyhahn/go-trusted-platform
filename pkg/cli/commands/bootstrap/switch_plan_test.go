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

package bootstrap

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
)

// TestPrintSwitchPlan prints each zone VLAN and each port's class, VLANs,
// native VLAN and MTU, and prints nothing for a nil plan.
func TestPrintSwitchPlan(t *testing.T) {
	out := captureStdout(t, func() {
		printSwitchPlan(&bootstrap.SwitchPlan{
			Vendor: "cisco-nexus",
			Host:   "192.0.2.10",
			VLANs:  []bootstrap.VLANPlan{{ID: 405, Name: "provisioning", Subnet: "192.0.2.0/24"}},
			Ports: []bootstrap.PortPlan{
				{Port: "Eth1/25", Class: "hypervisor", Mode: "trunk", VLANs: []int{401, 405}, NativeVLAN: 405, MTU: 9216},
				{Port: "Eth1/41", Class: "bmc", Mode: "access", VLANs: []int{402}, MTU: 9216},
			},
		})
	})
	for _, want := range []string{"VLAN 405", "provisioning", "192.0.2.0/24", "hypervisor", "[401,405]", "native 405", "mtu 9216", "native -"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if empty := captureStdout(t, func() { printSwitchPlan(nil) }); empty != "" {
		t.Fatalf("a nil plan must print nothing, got %q", empty)
	}
}
