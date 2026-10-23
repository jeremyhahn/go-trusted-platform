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

// BenchmarkSetEnrolments measures a gateway applying the enrolment set from a
// desired-config pull: validating it, refusing the peers that ask for a zone
// the gateway does not serve (one in fifty here), and sweeping the live
// leases the set no longer covers.
func BenchmarkSetEnrolments(b *testing.B) {
	for _, peers := range []int{100, 1000} {
		b.Run(fmt.Sprintf("peers=%d", peers), func(b *testing.B) {
			h := newHarness(b, testConfig())
			set := make([]Enrolment, 0, peers)
			for i := range peers {
				zone := "management"
				if i%50 == 0 {
					zone = "storage"
				}
				set = append(set, Enrolment{TenantID: fmt.Sprintf("tenant-%d", i%10), DeviceID: fmt.Sprintf("device-%d", i), Zones: []string{zone}})
			}
			ctx := context.Background()

			b.ReportAllocs()
			for b.Loop() {
				if err := h.svc.SetEnrolments(ctx, set); err != nil {
					b.Fatal(err)
				}
			}
			if got, want := len(h.svc.RejectedEnrolments()), (peers+49)/50; got != want {
				b.Fatalf("%d peers refused, want %d", got, want)
			}
		})
	}
}
