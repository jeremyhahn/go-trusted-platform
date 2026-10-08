// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
)

// verdictTestObserver records the observer calls a verdict produced.
type verdictTestObserver struct {
	passed []uint64
	failed []uint64
	detail []string
}

func (o *verdictTestObserver) OnAttestationFailed(_ context.Context, deviceID uint64, _ string, detail string) {
	o.failed = append(o.failed, deviceID)
	o.detail = append(o.detail, detail)
}

func (o *verdictTestObserver) OnAttestationPassed(_ context.Context, deviceID uint64, _ string) {
	o.passed = append(o.passed, deviceID)
}

func newVerdictService(t *testing.T) (*Service, *verdictTestObserver) {
	t.Helper()
	st, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	svc := NewService(st)
	obs := &verdictTestObserver{}
	svc.RegisterObserver(obs)
	return svc, obs
}

func eventKinds(t *testing.T, svc *Service, hostID string) []store.EventKind {
	t.Helper()
	events, err := svc.Store().ListEvents(store.EventFilter{HostID: hostID})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	kinds := make([]store.EventKind, 0, len(events))
	for _, e := range events {
		kinds = append(kinds, e.Kind)
	}
	return kinds
}

func TestRecordDeviceVerdict_PassNotifiesObserversAndLogs(t *testing.T) {
	svc, obs := newVerdictService(t)

	err := svc.RecordDeviceVerdict(context.Background(), verdict.DeviceVerdict{
		DeviceID: 7, HostID: "node-7", Serial: "SN7", Passed: true,
		BaselineSource: "signed", ProfileID: 3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(obs.passed) != 1 || obs.passed[0] != 7 {
		t.Fatalf("expected OnAttestationPassed(7), got passed=%v failed=%v", obs.passed, obs.failed)
	}
	kinds := eventKinds(t, svc, "node-7")
	if len(kinds) != 1 || kinds[0] != store.EventKindDeviceQuoteVerified {
		t.Fatalf("expected one device_quote_verified event, got %v", kinds)
	}
	events, _ := svc.Store().ListEvents(store.EventFilter{HostID: "node-7"})
	if events[0].Metadata["baseline_source"] != "signed" || events[0].Metadata["profile_id"] != "3" || events[0].Metadata["cryptographic"] != "false" {
		t.Fatalf("event metadata incomplete: %v", events[0].Metadata)
	}
}

func TestLatestDeviceVerdict_ReturnsNewestRecordedVerdict(t *testing.T) {
	svc, _ := newVerdictService(t)
	older := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	newer := older.Add(time.Minute)

	if err := svc.Store().PutEvent(&store.Event{
		ID:        "older-pass",
		Kind:      store.EventKindDeviceQuoteVerified,
		HostID:    "node-7",
		Timestamp: older,
		Outcome:   "pass",
		Metadata: map[string]string{
			"device_id":       "7",
			"serial":          "SN7",
			"cryptographic":   "false",
			"baseline_source": "signed",
			"profile_id":      "3",
		},
	}); err != nil {
		t.Fatalf("put older event: %v", err)
	}
	if err := svc.Store().PutEvent(&store.Event{
		ID:        "newer-fail",
		Kind:      store.EventKindDeviceQuoteRejected,
		HostID:    "node-7",
		Timestamp: newer,
		Outcome:   "fail",
		Reason:    "quote signature mismatch",
		Metadata: map[string]string{
			"device_id":       "7",
			"serial":          "SN7",
			"cryptographic":   "true",
			"baseline_source": "signed",
			"profile_id":      "3",
		},
	}); err != nil {
		t.Fatalf("put newer event: %v", err)
	}

	got, err := svc.LatestDeviceVerdict(context.Background(), 7)
	if err != nil {
		t.Fatalf("LatestDeviceVerdict: %v", err)
	}
	if got.EventID != "newer-fail" || !got.RecordedAt.Equal(newer) {
		t.Fatalf("expected newest event, got id=%q at=%s", got.EventID, got.RecordedAt)
	}
	if got.Verdict.Passed || !got.Verdict.Cryptographic || got.Verdict.BaselineSource != "signed" || got.Verdict.ProfileID != 3 {
		t.Fatalf("unexpected verdict: %+v", got.Verdict)
	}
}

func TestLatestDeviceVerdict_NotFoundIsTyped(t *testing.T) {
	svc, _ := newVerdictService(t)

	_, err := svc.LatestDeviceVerdict(context.Background(), 99)
	var notFound ErrDeviceVerdictNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrDeviceVerdictNotFound, got %v", err)
	}
	if notFound.DeviceID != 99 {
		t.Fatalf("wrong device id: %d", notFound.DeviceID)
	}
}

func TestRecordDeviceVerdict_CryptographicFailureQuarantines(t *testing.T) {
	svc, obs := newVerdictService(t)

	err := svc.RecordDeviceVerdict(context.Background(), verdict.DeviceVerdict{
		DeviceID: 8, HostID: "node-8", Passed: false, Cryptographic: true, Reason: "signature invalid",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(obs.failed) != 1 || obs.failed[0] != 8 || obs.detail[0] != "signature invalid" {
		t.Fatalf("expected OnAttestationFailed(8, signature invalid), got failed=%v detail=%v", obs.failed, obs.detail)
	}
	if len(obs.passed) != 0 {
		t.Fatal("a failed verdict must not be reported as passed")
	}
	kinds := eventKinds(t, svc, "node-8")
	if len(kinds) != 1 || kinds[0] != store.EventKindDeviceQuoteRejected {
		t.Fatalf("expected one device_quote_rejected event, got %v", kinds)
	}
	events, _ := svc.Store().ListEvents(store.EventFilter{HostID: "node-8"})
	if events[0].Metadata["cryptographic"] != "true" || events[0].Reason != "signature invalid" {
		t.Fatalf("event must carry the failure class and reason: %+v", events[0])
	}
}

func TestRecordDeviceVerdict_AbsenceOfEvidenceIsLoggedButNeverQuarantined(t *testing.T) {
	svc, obs := newVerdictService(t)

	err := svc.RecordDeviceVerdict(context.Background(), verdict.DeviceVerdict{
		DeviceID: 9, HostID: "node-9", Passed: false, Cryptographic: false, Reason: "no attestation certificate enrolled",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(obs.failed) != 0 || len(obs.passed) != 0 {
		t.Fatalf("absence of evidence must reach no observer, got passed=%v failed=%v", obs.passed, obs.failed)
	}
	kinds := eventKinds(t, svc, "node-9")
	if len(kinds) != 1 || kinds[0] != store.EventKindDeviceQuoteRejected {
		t.Fatalf("the denial is still logged: got %v", kinds)
	}
	events, _ := svc.Store().ListEvents(store.EventFilter{HostID: "node-9"})
	if events[0].Metadata["cryptographic"] != "false" {
		t.Fatalf("event must say the failure was not cryptographic: %v", events[0].Metadata)
	}
}

func TestRecordDeviceVerdict_BaselineCaptureIsItsOwnSecurityEvent(t *testing.T) {
	svc, _ := newVerdictService(t)

	err := svc.RecordDeviceVerdict(context.Background(), verdict.DeviceVerdict{
		DeviceID: 10, HostID: "node-10", Passed: true, BaselineCaptured: true, BaselineSource: "tofu", ProfileID: 4,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	captured, err := svc.Store().ListEvents(store.EventFilter{HostID: "node-10", Kind: store.EventKindPCRBaselineCaptured})
	if err != nil || len(captured) != 1 {
		t.Fatalf("expected one pcr_baseline_captured event, got %d (%v)", len(captured), err)
	}
	if captured[0].Metadata["profile_id"] != "4" || captured[0].Metadata["baseline_source"] != "tofu" {
		t.Fatalf("capture event must name the profile and source: %v", captured[0].Metadata)
	}
	verified, _ := svc.Store().ListEvents(store.EventFilter{HostID: "node-10", Kind: store.EventKindDeviceQuoteVerified})
	if len(verified) != 1 {
		t.Fatal("the verdict itself is still logged beside the capture")
	}
}

func TestRecordDeviceVerdict_RejectsInvalidVerdicts(t *testing.T) {
	svc, obs := newVerdictService(t)

	err := svc.RecordDeviceVerdict(context.Background(), verdict.DeviceVerdict{DeviceID: 0, Passed: true})
	if !errors.As(err, new(verdict.ErrInvalidVerdict)) {
		t.Fatalf("expected ErrInvalidVerdict, got %v", err)
	}
	err = svc.RecordDeviceVerdict(context.Background(), verdict.DeviceVerdict{DeviceID: 5, Passed: false})
	if !errors.As(err, new(verdict.ErrInvalidVerdict)) {
		t.Fatalf("a failed verdict without a reason must be rejected, got %v", err)
	}
	if len(obs.passed)+len(obs.failed) != 0 {
		t.Fatal("an invalid verdict reaches no observer")
	}
}

func TestNotifyObservers_ManifestPathStillResolvesDeviceByHost(t *testing.T) {
	svc, obs := newVerdictService(t)
	svc.SetDeviceResolver(hostResolver{"node-11": 11})

	svc.notifyObservers(context.Background(), "node-11", false, "manifest rejected")
	if len(obs.failed) != 1 || obs.failed[0] != 11 {
		t.Fatalf("the manifest path must keep resolving hosts to devices: %v", obs.failed)
	}
	svc.notifyObservers(context.Background(), "unknown-host", true, "")
	if len(obs.passed) != 1 || obs.passed[0] != 0 {
		t.Fatalf("an unresolvable host is delivered with device 0: %v", obs.passed)
	}
}

type hostResolver map[string]uint64

func (r hostResolver) DeviceForHost(hostID string) (uint64, bool) {
	id, ok := r[hostID]
	return id, ok
}
