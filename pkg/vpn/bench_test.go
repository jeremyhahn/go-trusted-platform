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
	"context"
	"fmt"
	"testing"
)

// BenchmarkDesiredVPN measures the vpn section the control plane renders for
// every gateway's desired-config pull: every enrolled peer and every posture
// policy, read from the store and copied into the section.
func BenchmarkDesiredVPN(b *testing.B) {
	for _, peers := range []int{100, 1000} {
		b.Run(fmt.Sprintf("peers=%d", peers), func(b *testing.B) {
			svc, _ := newTestService(b)
			ctx := context.Background()
			for i := range peers {
				tenant := fmt.Sprintf("tenant-%d", i%10)
				if _, err := svc.EnrolPeer(ctx, Peer{TenantID: tenant, DeviceID: fmt.Sprintf("device-%d", i), Zones: []string{"management"}}); err != nil {
					b.Fatal(err)
				}
			}
			for i := range 10 {
				if _, err := svc.SetPosturePolicy(ctx, PosturePolicy{TenantID: fmt.Sprintf("tenant-%d", i), Name: "vpn_posture", Module: testPolicy}); err != nil {
					b.Fatal(err)
				}
			}

			b.ReportAllocs()
			for b.Loop() {
				section, err := svc.DesiredVPN(ctx, "gw-1")
				if err != nil {
					b.Fatal(err)
				}
				if len(section.Peers) != peers {
					b.Fatalf("section carries %d peers, want %d", len(section.Peers), peers)
				}
			}
		})
	}
}
