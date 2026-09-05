// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

import (
	"context"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
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
