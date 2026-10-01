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

package netplan_test

import (
	"net/netip"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// BenchmarkNew measures deriving the plan of one environment, which every
// config load does once.
func BenchmarkNew(b *testing.B) {
	zones := zone.Defaults()
	env := netplan.Environment{ID: 4, ULA: ula}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := netplan.New(env, zones); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkZoneForAddr measures the address-to-zone lookup the installer and
// the policy engine run per address.
func BenchmarkZoneForAddr(b *testing.B) {
	p, err := netplan.New(netplan.Environment{ID: 4, ULA: ula}, zone.Defaults())
	if err != nil {
		b.Fatal(err)
	}
	addr := netip.MustParseAddr("10.4.8.77")
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := p.ZoneForAddr(addr); !ok {
			b.Fatal("no zone")
		}
	}
}

// BenchmarkPortClass measures deriving a port class's VLAN list.
func BenchmarkPortClass(b *testing.B) {
	p, err := netplan.New(netplan.Environment{ID: 4}, zone.Defaults())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := p.PortClass(zone.PortClassHypervisor); err != nil {
			b.Fatal(err)
		}
	}
}
