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
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// BridgeAddressConflictEventSource is the `source` field carried by the
// platform event the duplicate-address guard raises.
const BridgeAddressConflictEventSource = "sdn.addressing"

// bridgeAddressConflictEvent renders one refused bridge address as a platform
// event. The metadata carries both hardware addresses so a consumer never has
// to parse the message to identify the other station.
func bridgeAddressConflictEvent(index int, conflict app.BridgeAddressConflict) *platformv1.Event {
	return &platformv1.Event{
		Id:        fmt.Sprintf("sdn-address-conflict-%d", index),
		Type:      platformv1.EventType_EVENT_TYPE_ERROR,
		Severity:  platformv1.EventSeverity_EVENT_SEVERITY_CRITICAL,
		Timestamp: timestamppb.New(conflict.DetectedAt),
		Source:    BridgeAddressConflictEventSource,
		Message: fmt.Sprintf(
			"%s: %s was not assigned to bridge %s because %s already answers for it on this segment",
			AddressConflictMessage,
			conflict.Address,
			conflict.Bridge,
			conflict.ResponderHardwareAddr,
		),
		Metadata: map[string]string{
			"bridge":        conflict.Bridge,
			"address":       conflict.Address,
			"local_mac":     conflict.LocalHardwareAddr,
			"responder_mac": conflict.ResponderHardwareAddr,
		},
	}
}

// publishBridgeAddressConflicts raises one platform event per bridge address
// the guard refused during SDN bring-up.
//
// The guard runs inside App bring-up, long before any transport is listening,
// so the conflicts are recorded on the App and replayed here once the daemon's
// event stream exists. The event is the notification; the durable signal is
// the degraded `sdn-addressing` health component, which any client can read at
// any time.
func (d *Daemon) publishBridgeAddressConflicts() {
	if d.config == nil || d.config.App == nil {
		return
	}
	d.publishConflicts(d.config.App.BridgeAddressConflicts())
}

// publishConflicts raises one event per conflict and repeats the refusal in
// the daemon log, where an operator reading the daemon's own startup output
// sees it alongside the transports coming up.
func (d *Daemon) publishConflicts(conflicts []app.BridgeAddressConflict) {
	if d.service == nil {
		return
	}
	for i, conflict := range conflicts {
		d.service.PublishEvent(bridgeAddressConflictEvent(i, conflict))
		d.logger.Error(app.ErrBridgeAddressConflict{Conflict: conflict},
			"component", BridgeAddressConflictEventSource,
			"bridge", conflict.Bridge,
			"address", conflict.Address,
			"local_mac", conflict.LocalHardwareAddr,
			"responder_mac", conflict.ResponderHardwareAddr)
	}
}
