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

package daemon

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// deviceVerdictEvent renders a recorded device verdict as a platform event.
// A cryptographic failure is critical; an absence of evidence is a warning,
// because it denies service without being evidence of compromise.
func deviceVerdictEvent(recorded verdict.RecordedDeviceVerdict) *platformv1.Event {
	v := recorded.Verdict
	event := &platformv1.Event{
		Id:        recorded.EventID,
		Type:      platformv1.EventType_EVENT_TYPE_ATTESTATION_VERIFIED,
		Severity:  platformv1.EventSeverity_EVENT_SEVERITY_INFO,
		Timestamp: timestamppb.New(recorded.RecordedAt),
		Source:    verdict.EventSource,
		Message:   fmt.Sprintf("device %d quote verified", v.DeviceID),
		Metadata:  verdict.EventMetadata(v),
	}
	if !v.Passed {
		event.Severity = platformv1.EventSeverity_EVENT_SEVERITY_WARNING
		if v.Cryptographic {
			event.Severity = platformv1.EventSeverity_EVENT_SEVERITY_CRITICAL
		}
		event.Message = fmt.Sprintf("device %d quote rejected: %s", v.DeviceID, v.Reason)
	}
	return event
}

// deviceVerdictPublisher publishes every recorded device verdict on the
// daemon event stream.
type deviceVerdictPublisher struct {
	service *Service
}

// OnDeviceVerdict implements verdict.Observer.
func (p deviceVerdictPublisher) OnDeviceVerdict(_ context.Context, recorded verdict.RecordedDeviceVerdict) {
	p.service.PublishEvent(deviceVerdictEvent(recorded))
}

// publishDeviceVerdicts subscribes the daemon event stream to the attestation
// service's recorded device verdicts, which is how a failed verdict reaches
// the overlay gateways. It is a no-op when either side is not wired.
func (d *Daemon) publishDeviceVerdicts() {
	if d.service == nil || d.config == nil {
		return
	}
	registry, ok := d.config.AttestationService.(verdict.ObserverRegistry)
	if !ok {
		return
	}
	registry.RegisterDeviceVerdictObserver(deviceVerdictPublisher{service: d.service})
}
