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

package commands

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
)

// clockStatusReader is the one method the clock adapter needs from the
// platform's time service. *ntp.Service satisfies it.
type clockStatusReader interface {
	Status(ctx context.Context) (*ntp.Status, error)
}

// ntpClockAdapter projects the time service's status onto the narrow shape
// the attestation clock route serves.
//
// It exists so the attestation REST layer holds no NTP type and the NTP
// service knows nothing about attestation: the two features meet here, in
// the wiring, which is where the platform's cross-feature seams live.
type ntpClockAdapter struct {
	status clockStatusReader
}

// newNTPClockAdapter returns an adapter, or nil when this node runs no time
// service. A nil adapter leaves the clock route answering "not configured",
// which is the truth and is distinguishable from an unsynchronized clock.
func newNTPClockAdapter(status clockStatusReader) restattestation.ClockReader {
	// A typed nil behind the interface would pass a != nil check and then
	// panic on first use, so the nil case is answered with an untyped nil.
	if status == nil {
		return nil
	}
	return &ntpClockAdapter{status: status}
}

// ClockState implements restattestation.ClockReader.
//
// A read failure is returned as an error, never as a synced=false state:
// the route turns it into a 503 and the collector records the device's
// clock as unknown. Reporting "not synchronized" because a control socket
// was unreadable would put a fabricated verdict on a machine's clock.
func (a *ntpClockAdapter) ClockState(ctx context.Context) (restattestation.ClockState, error) {
	status, err := a.status.Status(ctx)
	if err != nil {
		return restattestation.ClockState{}, err
	}
	if status == nil {
		return restattestation.ClockState{}, ErrClockStatusEmpty{}
	}
	synced := status.Synced
	return restattestation.ClockState{
		Synced:           &synced,
		Stratum:          status.Stratum,
		LeapStatus:       status.LeapStatus,
		OffsetSeconds:    status.OffsetSeconds,
		SourcesReachable: status.SourcesReachable,
		SourcesTotal:     status.SourcesTotal,
		Anomaly:          status.Anomaly,
		AnomalyReason:    status.AnomalyReason,
	}, nil
}

// ErrClockStatusEmpty reports a time service that answered without error and
// without a status. It is a defect in the service, not a clock verdict.
type ErrClockStatusEmpty struct{}

func (ErrClockStatusEmpty) Error() string {
	return "attestation clock: the time service returned no status"
}
