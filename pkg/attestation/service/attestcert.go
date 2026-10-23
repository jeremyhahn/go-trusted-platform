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
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
)

// Compile-time check: the service is the platform's attestation-certificate
// record audit sink.
var _ verdict.AttestCertSink = (*Service)(nil)

// RecordAttestCert writes an attestation-certificate record attempt to the
// attestation event log. A recorded certificate becomes the trust anchor for
// every later quote from that device, so every outcome is audited: what was
// recorded and where it came from, what was refused and why, or — when the
// operator asked for it — which refused certificate was cleared and why.
//
// Observers are deliberately not notified. Recording a certificate is not a
// verdict about the device's measured state; the collector's next sweep
// verifies a quote against the new anchor and produces that verdict.
func (s *Service) RecordAttestCert(ctx context.Context, e verdict.AttestCertEvent) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	meta := map[string]string{
		"device_id": strconv.FormatUint(e.DeviceID, 10),
		"reissued":  strconv.FormatBool(e.Reissued),
	}
	if e.Serial != "" {
		meta["serial"] = e.Serial
	}
	if e.Source != "" {
		meta["source"] = e.Source
	}
	if e.Subject != "" {
		meta["subject"] = e.Subject
	}

	ev := &store.Event{
		Kind:     store.EventKindDeviceAttestCertRecorded,
		HostID:   e.HostID,
		CN:       e.HostID,
		Outcome:  "recorded",
		Metadata: meta,
	}
	switch {
	case e.Cleared:
		ev.Kind = store.EventKindDeviceAttestCertCleared
		ev.Outcome = "cleared"
		ev.Reason = e.Reason
	case !e.Recorded:
		ev.Kind = store.EventKindDeviceAttestCertRefused
		ev.Outcome = "refused"
		ev.Reason = e.Reason
	}
	return s.store.PutEvent(ev)
}
