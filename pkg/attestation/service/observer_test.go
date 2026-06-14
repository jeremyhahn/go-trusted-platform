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

package service

import (
	"context"
	"testing"
)

// ---- recording observer ----

type recordingObserver struct {
	failed []failedCall
	passed []passedCall
}

type failedCall struct {
	deviceID uint64
	hostID   string
	detail   string
}

type passedCall struct {
	deviceID uint64
	hostID   string
}

func (r *recordingObserver) OnAttestationFailed(_ context.Context, deviceID uint64, hostID, detail string) {
	r.failed = append(r.failed, failedCall{deviceID: deviceID, hostID: hostID, detail: detail})
}

func (r *recordingObserver) OnAttestationPassed(_ context.Context, deviceID uint64, hostID string) {
	r.passed = append(r.passed, passedCall{deviceID: deviceID, hostID: hostID})
}

var _ AttestationObserver = (*recordingObserver)(nil)

// ---- static resolver ----

type staticResolver struct {
	m map[string]uint64
}

func (s *staticResolver) DeviceForHost(hostID string) (uint64, bool) {
	id, ok := s.m[hostID]
	return id, ok
}

var _ DeviceResolver = (*staticResolver)(nil)

// ---- helper ----

func newService() *Service {
	return &Service{}
}

// ---- tests ----

func TestRegisterObserver_FailedDispatch(t *testing.T) {
	svc := newService()
	obs := &recordingObserver{}
	svc.RegisterObserver(obs)
	svc.SetDeviceResolver(&staticResolver{m: map[string]uint64{"host-1": 42}})

	svc.notifyObservers(context.Background(), "host-1", false, "PCR[4] mismatch")

	if len(obs.failed) != 1 {
		t.Fatalf("expected 1 failed call, got %d", len(obs.failed))
	}
	if obs.failed[0].deviceID != 42 {
		t.Errorf("expected deviceID 42, got %d", obs.failed[0].deviceID)
	}
	if obs.failed[0].hostID != "host-1" {
		t.Errorf("expected hostID host-1, got %s", obs.failed[0].hostID)
	}
	if obs.failed[0].detail != "PCR[4] mismatch" {
		t.Errorf("unexpected detail: %s", obs.failed[0].detail)
	}
	if len(obs.passed) != 0 {
		t.Error("expected no passed calls")
	}
}

func TestRegisterObserver_PassedDispatch(t *testing.T) {
	svc := newService()
	obs := &recordingObserver{}
	svc.RegisterObserver(obs)
	svc.SetDeviceResolver(&staticResolver{m: map[string]uint64{"host-2": 7}})

	svc.notifyObservers(context.Background(), "host-2", true, "")

	if len(obs.passed) != 1 {
		t.Fatalf("expected 1 passed call, got %d", len(obs.passed))
	}
	if obs.passed[0].deviceID != 7 {
		t.Errorf("expected deviceID 7, got %d", obs.passed[0].deviceID)
	}
	if obs.passed[0].hostID != "host-2" {
		t.Errorf("expected hostID host-2, got %s", obs.passed[0].hostID)
	}
	if len(obs.failed) != 0 {
		t.Error("expected no failed calls")
	}
}

func TestNotifyObservers_NoObservers_DoesNothing(t *testing.T) {
	svc := newService()
	// Must not panic when there are no observers.
	svc.notifyObservers(context.Background(), "host-x", false, "detail")
}

func TestNotifyObservers_NoResolver_DeviceIDZero(t *testing.T) {
	svc := newService()
	obs := &recordingObserver{}
	svc.RegisterObserver(obs)
	// No resolver installed.

	svc.notifyObservers(context.Background(), "host-3", false, "some detail")

	if len(obs.failed) != 1 {
		t.Fatalf("expected 1 failed call, got %d", len(obs.failed))
	}
	if obs.failed[0].deviceID != 0 {
		t.Errorf("expected deviceID 0 (no resolver), got %d", obs.failed[0].deviceID)
	}
}

func TestNotifyObservers_ResolverMiss_DeviceIDZero(t *testing.T) {
	svc := newService()
	obs := &recordingObserver{}
	svc.RegisterObserver(obs)
	svc.SetDeviceResolver(&staticResolver{m: map[string]uint64{}})

	svc.notifyObservers(context.Background(), "unknown-host", true, "")

	if len(obs.passed) != 1 {
		t.Fatalf("expected 1 passed call, got %d", len(obs.passed))
	}
	if obs.passed[0].deviceID != 0 {
		t.Errorf("expected deviceID 0 for resolver miss, got %d", obs.passed[0].deviceID)
	}
}

func TestNotifyObservers_MultipleObservers(t *testing.T) {
	svc := newService()
	obs1 := &recordingObserver{}
	obs2 := &recordingObserver{}
	svc.RegisterObserver(obs1)
	svc.RegisterObserver(obs2)
	svc.SetDeviceResolver(&staticResolver{m: map[string]uint64{"h": 99}})

	svc.notifyObservers(context.Background(), "h", false, "detail")

	if len(obs1.failed) != 1 {
		t.Errorf("obs1: expected 1 failed call, got %d", len(obs1.failed))
	}
	if len(obs2.failed) != 1 {
		t.Errorf("obs2: expected 1 failed call, got %d", len(obs2.failed))
	}
}

// ---- attestationDetail helper ----

func TestAttestationDetail_Empty(t *testing.T) {
	if got := attestationDetail(nil); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestAttestationDetail_Single(t *testing.T) {
	got := attestationDetail([]string{"PCR mismatch"})
	if got != "PCR mismatch" {
		t.Errorf("unexpected: %q", got)
	}
}

func TestAttestationDetail_Multiple(t *testing.T) {
	got := attestationDetail([]string{"err1", "err2", "err3"})
	if got != "err1 (+2 more)" {
		t.Errorf("unexpected: %q", got)
	}
}
