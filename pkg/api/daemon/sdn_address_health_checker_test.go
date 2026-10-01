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
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// stubConflictReporter reports a fixed set of refused bridge addresses and
// unguarded assignments.
type stubConflictReporter struct {
	conflicts   []app.BridgeAddressConflict
	unavailable []app.BridgeAddressProbeUnavailable
}

func (r *stubConflictReporter) BridgeAddressConflicts() []app.BridgeAddressConflict {
	return r.conflicts
}

func (r *stubConflictReporter) BridgeAddressProbeFailures() []app.BridgeAddressProbeUnavailable {
	return r.unavailable
}

func testProbeFailure() app.BridgeAddressProbeUnavailable {
	return app.BridgeAddressProbeUnavailable{
		Bridge:     "br-int",
		Address:    "198.18.0.2/24",
		Cause:      "arp: probe interface unavailable: operation not permitted",
		DetectedAt: time.Date(2026, 9, 6, 2, 40, 0, 0, time.UTC),
	}
}

func testConflict() app.BridgeAddressConflict {
	return app.BridgeAddressConflict{
		Bridge:                "br-int",
		Address:               "198.18.0.1/24",
		LocalHardwareAddr:     "02:00:00:00:00:01",
		ResponderHardwareAddr: "00:00:0c:9f:f0:14",
		DetectedAt:            time.Date(2026, 9, 6, 2, 40, 0, 0, time.UTC),
	}
}

func TestSDNAddressingHealthCheckerNilReporter(t *testing.T) {
	if checker := NewSDNAddressingHealthChecker(nil); checker != nil {
		t.Fatal("expected no checker without a reporter, so the component is absent")
	}

	// A zero-value checker must report unhealthy rather than panic.
	zero := &SDNAddressingHealthChecker{}
	result := zero.Check(context.Background())
	if result.Status != health.StatusUnhealthy {
		t.Fatalf("expected unhealthy for a nil reporter, got %s", result.Status)
	}
}

func TestSDNAddressingHealthCheckerHealthy(t *testing.T) {
	checker := NewSDNAddressingHealthChecker(&stubConflictReporter{})
	if checker.Name() != SDNAddressingHealthComponent {
		t.Fatalf("expected component %q, got %q", SDNAddressingHealthComponent, checker.Name())
	}

	result := checker.Check(context.Background())
	if result.Status != health.StatusHealthy {
		t.Fatalf("expected healthy with no conflicts, got %s", result.Status)
	}
	if count, ok := result.Details["conflict_count"].(int); !ok || count != 0 {
		t.Errorf("expected a zero conflict count, got %v", result.Details["conflict_count"])
	}
	if strings.Contains(result.Message, AddressConflictMessage) {
		t.Errorf("expected no conflict marker in a healthy message, got %q", result.Message)
	}
	if strings.Contains(result.Message, ProbeUnavailableMessage) {
		t.Errorf("expected no probe marker in a healthy message, got %q", result.Message)
	}
	if count, ok := result.Details["probe_unavailable_count"].(int); !ok || count != 0 {
		t.Errorf("expected a zero probe-failure count, got %v", result.Details["probe_unavailable_count"])
	}
}

// TestSDNAddressingHealthCheckerProbeUnavailable is the claim that a node
// which silently lost the guard must not look healthy: the address is on the
// wire, nothing checked it, and the component says so.
func TestSDNAddressingHealthCheckerProbeUnavailable(t *testing.T) {
	failure := testProbeFailure()
	checker := NewSDNAddressingHealthChecker(&stubConflictReporter{
		unavailable: []app.BridgeAddressProbeUnavailable{failure},
	})

	result := checker.Check(context.Background())
	if result.Status != health.StatusDegraded {
		t.Fatalf("expected degraded when an address went on unprobed, got %s", result.Status)
	}
	if !strings.HasPrefix(result.Message, ProbeUnavailableMessage) {
		t.Errorf("expected the message to lead with %q, got %q", ProbeUnavailableMessage, result.Message)
	}
	for _, want := range []string{failure.Address, failure.Bridge, failure.Cause} {
		if !strings.Contains(result.Message, want) {
			t.Errorf("expected the message to name %q, got %q", want, result.Message)
		}
	}
	reported, ok := result.Details["probe_unavailable"].([]map[string]any)
	if !ok || len(reported) != 1 {
		t.Fatalf("expected one reported probe failure in details, got %v", result.Details["probe_unavailable"])
	}
	if reported[0]["cause"] != failure.Cause {
		t.Errorf("expected the cause in details, got %v", reported[0]["cause"])
	}
	if reported[0]["bridge"] != failure.Bridge || reported[0]["address"] != failure.Address {
		t.Errorf("expected the bridge and address in details, got %v", reported[0])
	}
	if _, present := result.Details["conflicts"]; present {
		t.Error("expected no conflict details when nothing was refused")
	}
}

// TestSDNAddressingHealthCheckerMultipleProbeFailures proves the summary
// counts the addresses it does not name.
func TestSDNAddressingHealthCheckerMultipleProbeFailures(t *testing.T) {
	second := testProbeFailure()
	second.Bridge = "public0"
	checker := NewSDNAddressingHealthChecker(&stubConflictReporter{
		unavailable: []app.BridgeAddressProbeUnavailable{testProbeFailure(), second},
	})

	result := checker.Check(context.Background())
	if !strings.Contains(result.Message, "and 1 more") {
		t.Errorf("expected the message to count the remaining failures, got %q", result.Message)
	}
	if count, ok := result.Details["probe_unavailable_count"].(int); !ok || count != 2 {
		t.Errorf("expected a probe-failure count of 2, got %v", result.Details["probe_unavailable_count"])
	}
}

// TestSDNAddressingHealthCheckerBothFailures proves the two failures are
// reported as the different things they are, with the live consequence first.
func TestSDNAddressingHealthCheckerBothFailures(t *testing.T) {
	checker := NewSDNAddressingHealthChecker(&stubConflictReporter{
		conflicts:   []app.BridgeAddressConflict{testConflict()},
		unavailable: []app.BridgeAddressProbeUnavailable{testProbeFailure()},
	})

	result := checker.Check(context.Background())
	if result.Status != health.StatusDegraded {
		t.Fatalf("expected degraded, got %s", result.Status)
	}
	if !strings.HasPrefix(result.Message, AddressConflictMessage) {
		t.Errorf("expected the refusal to lead the message, got %q", result.Message)
	}
	if !strings.Contains(result.Message, ProbeUnavailableMessage) {
		t.Errorf("expected the missing probe to be reported too, got %q", result.Message)
	}
	if _, ok := result.Details["conflicts"]; !ok {
		t.Error("expected conflict details")
	}
	if _, ok := result.Details["probe_unavailable"]; !ok {
		t.Error("expected probe-failure details")
	}
}

func TestSDNAddressingHealthCheckerDegraded(t *testing.T) {
	conflict := testConflict()
	checker := NewSDNAddressingHealthChecker(&stubConflictReporter{
		conflicts: []app.BridgeAddressConflict{conflict},
	})

	result := checker.Check(context.Background())
	if result.Status != health.StatusDegraded {
		t.Fatalf("expected degraded after a refused address, got %s", result.Status)
	}
	if !strings.HasPrefix(result.Message, AddressConflictMessage) {
		t.Errorf("expected the message to lead with %q, got %q", AddressConflictMessage, result.Message)
	}
	for _, want := range []string{conflict.Address, conflict.Bridge, conflict.ResponderHardwareAddr} {
		if !strings.Contains(result.Message, want) {
			t.Errorf("expected the message to name %q, got %q", want, result.Message)
		}
	}
	reported, ok := result.Details["conflicts"].([]map[string]any)
	if !ok || len(reported) != 1 {
		t.Fatalf("expected one reported conflict in details, got %v", result.Details["conflicts"])
	}
	if reported[0]["local_mac"] != conflict.LocalHardwareAddr {
		t.Errorf("expected the local MAC in details, got %v", reported[0]["local_mac"])
	}
	if reported[0]["responder_mac"] != conflict.ResponderHardwareAddr {
		t.Errorf("expected the responder MAC in details, got %v", reported[0]["responder_mac"])
	}
	if _, present := result.Details["probe_unavailable"]; present {
		t.Error("expected no probe-failure details when every address was probed")
	}
}

func TestSDNAddressingHealthCheckerMultipleConflicts(t *testing.T) {
	first := testConflict()
	second := testConflict()
	second.Bridge = "public0"
	second.Address = "203.0.113.1/24"

	checker := NewSDNAddressingHealthChecker(&stubConflictReporter{
		conflicts: []app.BridgeAddressConflict{first, second},
	})

	result := checker.Check(context.Background())
	if result.Status != health.StatusDegraded {
		t.Fatalf("expected degraded, got %s", result.Status)
	}
	if !strings.Contains(result.Message, "and 1 more") {
		t.Errorf("expected the message to count the remaining conflicts, got %q", result.Message)
	}
	if count, ok := result.Details["conflict_count"].(int); !ok || count != 2 {
		t.Errorf("expected a conflict count of 2, got %v", result.Details["conflict_count"])
	}
}

func TestBridgeAddressConflictEvent(t *testing.T) {
	conflict := testConflict()
	event := bridgeAddressConflictEvent(0, conflict)

	if event.Type != platformv1.EventType_EVENT_TYPE_ERROR {
		t.Errorf("expected an error event, got %s", event.Type)
	}
	if event.Severity != platformv1.EventSeverity_EVENT_SEVERITY_CRITICAL {
		t.Errorf("expected critical severity, got %s", event.Severity)
	}
	if event.Source != BridgeAddressConflictEventSource {
		t.Errorf("expected source %q, got %q", BridgeAddressConflictEventSource, event.Source)
	}
	if !strings.Contains(event.Message, AddressConflictMessage) {
		t.Errorf("expected the conflict marker in the message, got %q", event.Message)
	}
	if event.Metadata["responder_mac"] != conflict.ResponderHardwareAddr {
		t.Errorf("expected the responder MAC in metadata, got %q", event.Metadata["responder_mac"])
	}
	if event.Metadata["local_mac"] != conflict.LocalHardwareAddr {
		t.Errorf("expected the local MAC in metadata, got %q", event.Metadata["local_mac"])
	}
	if event.Metadata["bridge"] != conflict.Bridge || event.Metadata["address"] != conflict.Address {
		t.Errorf("expected the bridge and address in metadata, got %v", event.Metadata)
	}
	if event.Timestamp.AsTime() != conflict.DetectedAt {
		t.Errorf("expected the detection time, got %s", event.Timestamp.AsTime())
	}
}

func TestPublishBridgeAddressConflictsReachesSubscribers(t *testing.T) {
	service, err := NewService(nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	daemon := &Daemon{service: service, logger: discardLogger()}

	events := make(chan *platformv1.Event, 4)
	service.subMu.Lock()
	service.eventSubs["test"] = events
	service.subMu.Unlock()

	daemon.publishConflicts([]app.BridgeAddressConflict{testConflict()})

	select {
	case event := <-events:
		if event.Source != BridgeAddressConflictEventSource {
			t.Fatalf("expected the addressing event, got source %q", event.Source)
		}
	default:
		t.Fatal("expected a platform event for the refused address")
	}
}

func TestPublishBridgeAddressConflictsWithoutWiring(t *testing.T) {
	// Nothing wired: the replay must be a no-op rather than a panic.
	(&Daemon{logger: discardLogger()}).publishBridgeAddressConflicts()
	(&Daemon{config: &Config{}, logger: discardLogger()}).publishBridgeAddressConflicts()
	(&Daemon{config: &Config{App: &app.App{}}, logger: discardLogger()}).publishBridgeAddressConflicts()

	// An App with a conflict but no event service must not publish and must
	// not panic either.
	(&Daemon{logger: discardLogger()}).publishConflicts([]app.BridgeAddressConflict{testConflict()})
}

// discardLogger builds a daemon logger that writes nowhere.
func discardLogger() *logging.Logger {
	return logging.NewLoggerWithFormat(slog.LevelError, logging.FormatJSON, io.Discard)
}
