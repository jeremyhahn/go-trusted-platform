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

// An advertised NTS-KE name the node's own allow list refuses (#509
// follow-up). The clock can be perfectly disciplined while the node hands
// out a certificate for a name whose address it will not answer: the
// handshake succeeds and the time never arrives.

func serveNameFinding() ntp.ServeNameFinding {
	return ntp.ServeNameFinding{
		Kind:           ntp.ServeNameUnreachable,
		Name:           "cp.example.internal",
		Address:        "10.4.2.140",
		ListenNetworks: []string{"10.4.200.0/24", "192.0.2.0/24"},
	}
}

func unresolvableFinding() ntp.ServeNameFinding {
	return ntp.ServeNameFinding{
		Kind:  ntp.ServeNameUnresolvable,
		Name:  "time.example.internal",
		Error: "lookup time.example.internal: no such host",
	}
}

// TestNTPHealthCheckerFlagsAnUnreachableServeName asserts a healthy clock
// with a refused serve name is DEGRADED, and that the message names the
// name, the address and the allow list so the operator can reconcile them
// without a second command.
func TestNTPHealthCheckerFlagsAnUnreachableServeName(t *testing.T) {
	status := syncedNTPStatus()
	status.ServeNameFindings = []ntp.ServeNameFinding{serveNameFinding()}

	result := NewNTPServiceHealthChecker(&fakeNTPBackend{status: status}).Check(context.Background())

	if result.Status != health.StatusDegraded {
		t.Fatalf("Status = %v (%s), want degraded", result.Status, result.Message)
	}
	if !strings.Contains(result.Message, string(ntp.ServeNameUnreachable)) {
		t.Fatalf("message %q must carry the %q marker for fleet monitoring",
			result.Message, string(ntp.ServeNameUnreachable))
	}
	for _, want := range []string{"cp.example.internal", "10.4.2.140", "10.4.200.0/24"} {
		if !strings.Contains(result.Message, want) {
			t.Errorf("message %q does not name %q", result.Message, want)
		}
	}
	// The clock is fine, so the clock marker must NOT appear: an operator
	// chasing time-unsynced here would be chasing the wrong fault.
	if strings.Contains(result.Message, TimeUnsyncedMessage) {
		t.Errorf("a serve-name mismatch must not be reported as an unsynced clock: %q", result.Message)
	}
	if _, ok := result.Details["serve_name_findings"]; !ok {
		t.Error("details must carry the structured findings")
	}
	names, _ := result.Details["serve_names_affected"].([]string)
	if len(names) != 1 || names[0] != "cp.example.internal" {
		t.Errorf("serve_names_unreachable = %v", names)
	}
}

// TestNTPHealthCheckerReportsBothConditions asserts an unsynced clock AND a
// refused serve name are reported together. Collapsing to one would hide a
// serving-side misconfiguration behind an unrelated clock problem, which is
// exactly how #509 stayed invisible.
func TestNTPHealthCheckerReportsBothConditions(t *testing.T) {
	result := NewNTPServiceHealthChecker(&fakeNTPBackend{status: &ntp.Status{
		Synced:            false,
		LeapStatus:        ntp.LeapNotSynchronised,
		Mode:              "both",
		ServeNameFindings: []ntp.ServeNameFinding{serveNameFinding()},
	}}).Check(context.Background())

	if result.Status != health.StatusDegraded {
		t.Fatalf("Status = %v, want degraded", result.Status)
	}
	if !strings.Contains(result.Message, TimeUnsyncedMessage) {
		t.Errorf("message %q lost the clock marker", result.Message)
	}
	if !strings.Contains(result.Message, string(ntp.ServeNameUnreachable)) {
		t.Errorf("message %q lost the serve-name marker", result.Message)
	}
}

// TestNTPHealthCheckerHealthyWithNoFindings covers the other side: no
// findings adds no detail keys and leaves the component healthy.
func TestNTPHealthCheckerHealthyWithNoFindings(t *testing.T) {
	result := NewNTPServiceHealthChecker(&fakeNTPBackend{status: syncedNTPStatus()}).Check(context.Background())
	if result.Status != health.StatusHealthy {
		t.Fatalf("Status = %v (%s), want healthy", result.Status, result.Message)
	}
	if _, ok := result.Details["serve_name_findings"]; ok {
		t.Error("no findings must add no findings detail")
	}
}

// TestNTPHealthCheckerFlagsAnUnresolvableServeName asserts the second finding
// kind reaches the health surface with its own marker and the resolver's own
// words. On this fleet nodes forward the internal zone through the control
// plane, so a name the control plane cannot resolve is one no node can reach
// — the same silent failure as an allow-list refusal, but a different fault
// with a different fix, so it must not be reported as the other one.
func TestNTPHealthCheckerFlagsAnUnresolvableServeName(t *testing.T) {
	status := syncedNTPStatus()
	status.ServeNameFindings = []ntp.ServeNameFinding{unresolvableFinding()}

	result := NewNTPServiceHealthChecker(&fakeNTPBackend{status: status}).Check(context.Background())

	if result.Status != health.StatusDegraded {
		t.Fatalf("Status = %v (%s), want degraded", result.Status, result.Message)
	}
	if !strings.Contains(result.Message, string(ntp.ServeNameUnresolvable)) {
		t.Fatalf("message %q must carry the %q marker", result.Message, ntp.ServeNameUnresolvable)
	}
	if strings.Contains(result.Message, string(ntp.ServeNameUnreachable)) {
		t.Errorf("an unresolvable name must not be reported as an allow-list refusal: %q", result.Message)
	}
	for _, want := range []string{"time.example.internal", "no such host"} {
		if !strings.Contains(result.Message, want) {
			t.Errorf("message %q does not name %q", result.Message, want)
		}
	}
	if strings.Contains(result.Message, TimeUnsyncedMessage) {
		t.Errorf("the clock is fine and must not be flagged: %q", result.Message)
	}
}

// TestNTPHealthCheckerReportsBothServeNameKinds asserts a node advertising
// one name it refuses and one it cannot resolve reports both markers, so an
// operator sees two faults rather than one.
func TestNTPHealthCheckerReportsBothServeNameKinds(t *testing.T) {
	status := syncedNTPStatus()
	status.ServeNameFindings = []ntp.ServeNameFinding{serveNameFinding(), unresolvableFinding()}

	result := NewNTPServiceHealthChecker(&fakeNTPBackend{status: status}).Check(context.Background())

	for _, marker := range []ntp.ServeNameFindingKind{ntp.ServeNameUnreachable, ntp.ServeNameUnresolvable} {
		if !strings.Contains(result.Message, string(marker)) {
			t.Errorf("message %q lost the %q marker", result.Message, marker)
		}
	}
	names, _ := result.Details["serve_names_affected"].([]string)
	if len(names) != 2 {
		t.Errorf("serve_names_affected = %v, want both names", names)
	}
}
