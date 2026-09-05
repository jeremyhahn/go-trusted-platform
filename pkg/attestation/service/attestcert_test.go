// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
)

func TestRecordAttestCert_RecordedWritesEventAndNeverNotifiesObservers(t *testing.T) {
	svc, obs := newVerdictService(t)

	err := svc.RecordAttestCert(context.Background(), verdict.AttestCertEvent{
		DeviceID: 7,
		HostID:   "node-07",
		Serial:   "SN7",
		Recorded: true,
		Source:   "reissued",
		Subject:  "CN=iak-X10-SN7",
		Reissued: true,
	})
	if err != nil {
		t.Fatalf("RecordAttestCert: %v", err)
	}

	events, err := svc.Store().ListEvents(store.EventFilter{HostID: "node-07"})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != store.EventKindDeviceAttestCertRecorded || ev.Outcome != "recorded" {
		t.Fatalf("unexpected event: kind=%s outcome=%s", ev.Kind, ev.Outcome)
	}
	for k, want := range map[string]string{
		"device_id": "7", "serial": "SN7", "source": "reissued", "subject": "CN=iak-X10-SN7", "reissued": "true",
	} {
		if ev.Metadata[k] != want {
			t.Errorf("metadata[%s] = %q, want %q", k, ev.Metadata[k], want)
		}
	}
	if len(obs.passed) != 0 || len(obs.failed) != 0 {
		t.Fatalf("recording a certificate must not reach the quarantine observers: %+v", obs)
	}
}

func TestRecordAttestCert_RefusedWritesReasonAndNeverNotifiesObservers(t *testing.T) {
	svc, obs := newVerdictService(t)

	err := svc.RecordAttestCert(context.Background(), verdict.AttestCertEvent{
		DeviceID: 8,
		HostID:   "node-08",
		Reason:   "device: certificate does not carry tcg-cap-verifiedTPMRestricted",
	})
	if err != nil {
		t.Fatalf("RecordAttestCert: %v", err)
	}

	events, err := svc.Store().ListEvents(store.EventFilter{HostID: "node-08"})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != store.EventKindDeviceAttestCertRefused || ev.Outcome != "refused" {
		t.Fatalf("unexpected event: kind=%s outcome=%s", ev.Kind, ev.Outcome)
	}
	if ev.Reason == "" || ev.Metadata["reissued"] != "false" {
		t.Fatalf("refusal must carry the reason and the reissue flag: %+v", ev)
	}
	if len(obs.passed) != 0 || len(obs.failed) != 0 {
		t.Fatalf("a refused record attempt must not reach the quarantine observers: %+v", obs)
	}
}

func TestRecordAttestCert_RejectsInvalidEvents(t *testing.T) {
	svc, _ := newVerdictService(t)
	for name, ev := range map[string]verdict.AttestCertEvent{
		"no device":               {Recorded: true, Source: "ca"},
		"recorded with reason":    {DeviceID: 1, Recorded: true, Source: "ca", Reason: "x"},
		"recorded without source": {DeviceID: 1, Recorded: true},
		"refused without reason":  {DeviceID: 1},
	} {
		t.Run(name, func(t *testing.T) {
			err := svc.RecordAttestCert(context.Background(), ev)
			var invalid verdict.ErrInvalidVerdict
			if !errors.As(err, &invalid) {
				t.Fatalf("want ErrInvalidVerdict, got %v", err)
			}
		})
	}
	if kinds := eventKinds(t, svc, ""); len(kinds) != 0 {
		t.Fatalf("invalid events must not be written: %v", kinds)
	}
}

func TestRecordAttestCert_CancelledContextIsAnError(t *testing.T) {
	svc, _ := newVerdictService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := svc.RecordAttestCert(ctx, verdict.AttestCertEvent{DeviceID: 1, Reason: "refused"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
