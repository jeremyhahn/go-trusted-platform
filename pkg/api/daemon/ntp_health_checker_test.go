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

package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
)

func TestNTPHealthCheckerReportsHealthyOnAConvergedClock(t *testing.T) {
	checker := NewNTPServiceHealthChecker(&fakeNTPBackend{status: syncedNTPStatus()})
	if checker == nil {
		t.Fatal("NewNTPServiceHealthChecker() = nil for a configured backend")
	}
	if checker.Name() != "ntp" {
		t.Fatalf("Name() = %q, want ntp", checker.Name())
	}

	result := checker.Check(context.Background())
	if result.Status != health.StatusHealthy {
		t.Fatalf("Status = %v (%s), want healthy", result.Status, result.Message)
	}
	if result.Details["stratum"] != uint32(3) {
		t.Fatalf("stratum detail = %v, want 3", result.Details["stratum"])
	}
	if strings.Contains(result.Message, TimeUnsyncedMessage) {
		t.Fatalf("healthy clock should not be flagged: %q", result.Message)
	}
}

func TestNTPHealthCheckerFlagsUnsyncedAndAnomalousClocks(t *testing.T) {
	cases := map[string]struct {
		backend NTPBackend
		want    health.HealthStatus
	}{
		"unsynchronized": {
			backend: &fakeNTPBackend{status: &ntp.Status{
				Synced:     false,
				LeapStatus: ntp.LeapNotSynchronised,
				Mode:       "consume",
			}},
			want: health.StatusDegraded,
		},
		"post-convergence anomaly": {
			backend: &fakeNTPBackend{status: &ntp.Status{
				Synced:        true,
				Stratum:       3,
				LeapStatus:    "Normal",
				Anomaly:       true,
				AnomalyReason: "clock corrected by 42.000s after the first-boot correction",
				Mode:          "consume",
			}},
			want: health.StatusDegraded,
		},
		"control socket unreachable": {
			backend: &fakeNTPBackend{statusErr: ntp.ErrControlUnavailable{Command: "tracking"}},
			want:    health.StatusUnhealthy,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			result := NewNTPServiceHealthChecker(tc.backend).Check(context.Background())
			if result.Status != tc.want {
				t.Fatalf("Status = %v, want %v", result.Status, tc.want)
			}
			if !strings.Contains(result.Message, TimeUnsyncedMessage) {
				t.Fatalf("message %q must carry the %q marker for fleet monitoring",
					result.Message, TimeUnsyncedMessage)
			}
		})
	}
}

func TestNTPHealthCheckerIsAbsentWithoutABackend(t *testing.T) {
	if checker := NewNTPServiceHealthChecker(nil); checker != nil {
		t.Fatal("NewNTPServiceHealthChecker(nil) should return nil so the component is simply absent")
	}

	// A checker whose backend was cleared after construction must report
	// unhealthy rather than panic.
	checker := &NTPServiceHealthChecker{}
	result := checker.Check(context.Background())
	if result.Status != health.StatusUnhealthy {
		t.Fatalf("Status = %v, want unhealthy", result.Status)
	}
}
