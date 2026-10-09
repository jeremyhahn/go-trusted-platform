// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

import (
	"context"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"strconv"
)

// Compile-time check: the service is the platform's verdict sink.
var _ verdict.Sink = (*Service)(nil)

// RecordDeviceVerdict writes the verdict to the attestation event log and
// hands it to the registered observers, which is how a failed device quote
// reaches the SDN quarantine manager.
//
// Only a cryptographic failure is reported to observers as a failure. An
// absence of evidence (no attestation certificate, no profile, no trust
// anchor) is logged and denied service by the verifier, but it is not
// evidence of compromise and never quarantines a device. A captured
// trust-on-first-use baseline is logged as its own security event so the
// moment a profile's expected PCR state was set is auditable.
func (s *Service) RecordDeviceVerdict(ctx context.Context, v verdict.DeviceVerdict) error {
	if err := v.Validate(); err != nil {
		return err
	}

	meta := map[string]string{
		"device_id":     strconv.FormatUint(v.DeviceID, 10),
		"cryptographic": strconv.FormatBool(!v.Passed && v.Cryptographic),
	}
	if v.Serial != "" {
		meta["serial"] = v.Serial
	}
	if v.ProfileID != 0 {
		meta["profile_id"] = strconv.FormatUint(v.ProfileID, 10)
	}
	if v.BaselineSource != "" {
		meta["baseline_source"] = v.BaselineSource
	}

	if v.BaselineCaptured {
		if err := s.store.PutEvent(&store.Event{
			Kind:     store.EventKindPCRBaselineCaptured,
			HostID:   v.HostID,
			CN:       v.HostID,
			Outcome:  "captured",
			Metadata: meta,
		}); err != nil {
			return err
		}
	}

	ev := &store.Event{
		Kind:     store.EventKindDeviceQuoteVerified,
		HostID:   v.HostID,
		CN:       v.HostID,
		Outcome:  "pass",
		Metadata: meta,
	}
	if !v.Passed {
		ev.Kind = store.EventKindDeviceQuoteRejected
		ev.Outcome = "fail"
		ev.Reason = v.Reason
	}
	if err := s.store.PutEvent(ev); err != nil {
		return err
	}

	switch {
	case v.Passed:
		s.dispatchVerdict(ctx, v.DeviceID, v.HostID, true, "")
	case v.Cryptographic:
		s.dispatchVerdict(ctx, v.DeviceID, v.HostID, false, v.Reason)
	}
	return nil
}

// ErrDeviceVerdictNotFound is returned when no device quote verdict has been
// recorded for a device.
type ErrDeviceVerdictNotFound struct {
	DeviceID uint64
}

func (e ErrDeviceVerdictNotFound) Error() string {
	return "attestation/service: latest device verdict not found for device " + strconv.FormatUint(e.DeviceID, 10)
}

// LatestDeviceVerdict returns the newest recorded device quote verdict for the
// device. The attestation event store is the source of truth: it already holds
// the durable verdict trail and supplies the freshness timestamp used by
// relying-party admission checks.
func (s *Service) LatestDeviceVerdict(ctx context.Context, deviceID uint64) (*verdict.RecordedDeviceVerdict, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if deviceID == 0 {
		return nil, ErrDeviceVerdictNotFound{DeviceID: deviceID}
	}

	events, err := s.store.ListEvents(store.EventFilter{})
	if err != nil {
		return nil, err
	}
	want := strconv.FormatUint(deviceID, 10)
	for _, ev := range events {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if ev == nil || ev.Metadata["device_id"] != want {
			continue
		}
		switch ev.Kind {
		case store.EventKindDeviceQuoteVerified, store.EventKindDeviceQuoteRejected:
			return recordedVerdictFromEvent(ev, deviceID), nil
		default:
			continue
		}
	}
	return nil, ErrDeviceVerdictNotFound{DeviceID: deviceID}
}

func recordedVerdictFromEvent(ev *store.Event, deviceID uint64) *verdict.RecordedDeviceVerdict {
	passed := ev.Kind == store.EventKindDeviceQuoteVerified
	profileID, _ := strconv.ParseUint(ev.Metadata["profile_id"], 10, 64)
	return &verdict.RecordedDeviceVerdict{
		Verdict: verdict.DeviceVerdict{
			DeviceID:       deviceID,
			HostID:         ev.HostID,
			Serial:         ev.Metadata["serial"],
			Passed:         passed,
			Cryptographic:  ev.Metadata["cryptographic"] == "true",
			Reason:         ev.Reason,
			BaselineSource: ev.Metadata["baseline_source"],
			ProfileID:      profileID,
		},
		EventID:    ev.ID,
		RecordedAt: ev.Timestamp,
	}
}

// dispatchVerdict fans one attestation outcome out to every registered
// observer. deviceID may be zero when the caller only knows the host.
func (s *Service) dispatchVerdict(ctx context.Context, deviceID uint64, hostID string, passed bool, detail string) {
	s.mu.RLock()
	obs := s.observers
	s.mu.RUnlock()

	for _, o := range obs {
		if passed {
			o.OnAttestationPassed(ctx, deviceID, hostID)
		} else {
			o.OnAttestationFailed(ctx, deviceID, hostID, detail)
		}
	}
}
