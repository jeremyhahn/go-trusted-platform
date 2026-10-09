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

package verdict

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// EventOf renders a recorded device verdict for the wire. Every transport of
// the verdict stream (gRPC, Unix, REST) sends this one shape.
func EventOf(recorded RecordedDeviceVerdict) *platformv1.DeviceVerdictEvent {
	v := recorded.Verdict
	return &platformv1.DeviceVerdictEvent{
		EventId:       recorded.EventID,
		RecordedAt:    timestamppb.New(recorded.RecordedAt),
		DeviceId:      v.DeviceID,
		TenantId:      v.TenantID,
		HostId:        v.HostID,
		Serial:        v.Serial,
		Passed:        v.Passed,
		Cryptographic: v.Cryptographic,
		Reason:        v.Reason,
	}
}
