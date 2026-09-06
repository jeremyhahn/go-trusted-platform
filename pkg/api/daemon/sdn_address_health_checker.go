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
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
)

// AddressConflictMessage is the health message a node reports while a
// configured bridge address was refused because another station on the
// segment already answers for it. Fleet monitoring keys on it: the node keeps
// serving on its remaining addresses, but the refused address is not on the
// wire and anything that depends on it is broken until an operator
// re-addresses one of the two stations.
const AddressConflictMessage = "address-conflict"

// ProbeUnavailableMessage is the health message a node reports while a
// configured bridge address is on the wire but was never probed, because the
// duplicate-address guard could not run. The address may be fine; what is
// missing is the evidence. Without this the node would look healthy, which is
// the one outcome a guard must never produce when it has silently stopped
// guarding.
const ProbeUnavailableMessage = "probe-unavailable"

// SDNAddressingHealthComponent is the health component name the
// duplicate-address guard reports under.
const SDNAddressingHealthComponent = "sdn-addressing"

// BridgeAddressReporter reports what the duplicate-address guard learned
// during SDN bring-up. *app.App implements it.
type BridgeAddressReporter interface {
	// BridgeAddressConflicts returns the refused addresses, empty when the
	// guard found no conflict.
	BridgeAddressConflicts() []app.BridgeAddressConflict

	// BridgeAddressProbeFailures returns the addresses assigned without a
	// probe, empty when every configured address was actually guarded.
	BridgeAddressProbeFailures() []app.BridgeAddressProbeUnavailable
}

// SDNAddressingHealthChecker reports whether every configured bridge address
// made it onto the wire, and whether each one was actually probed first.
type SDNAddressingHealthChecker struct {
	reporter BridgeAddressReporter
}

// NewSDNAddressingHealthChecker creates the addressing health checker. It
// returns nil when there is no reporter, so the component is absent rather
// than permanently unknown.
func NewSDNAddressingHealthChecker(reporter BridgeAddressReporter) *SDNAddressingHealthChecker {
	if reporter == nil {
		return nil
	}
	return &SDNAddressingHealthChecker{reporter: reporter}
}

// Name returns the health component name.
func (c *SDNAddressingHealthChecker) Name() string { return SDNAddressingHealthComponent }

// Check reports degraded for as long as any configured bridge address was
// refused, and for as long as any address went onto the wire unprobed. Both
// states are sticky by design: the guard runs once at bring-up, so clearing
// either takes an operator fixing the cause and restarting the node.
//
// A refusal and a missing probe are different failures and are reported as
// such. A refused address is not on the wire and something is broken now; an
// unprobed address is on the wire and may be perfectly fine, but nothing
// checked. When both are present the refusal leads the message, because it is
// the one with a live consequence.
func (c *SDNAddressingHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	start := time.Now()
	componentHealth := health.ComponentHealth{
		Name:        c.Name(),
		Status:      health.StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.reporter == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "bridge address conflict reporter reference is nil"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	conflicts := c.reporter.BridgeAddressConflicts()
	unavailable := c.reporter.BridgeAddressProbeFailures()
	componentHealth.Details["conflict_count"] = len(conflicts)
	componentHealth.Details["probe_unavailable_count"] = len(unavailable)

	if len(conflicts) == 0 && len(unavailable) == 0 {
		componentHealth.Status = health.StatusHealthy
		componentHealth.Message = "every configured bridge address was probed and assigned"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	messages := make([]string, 0, 2)

	if len(conflicts) > 0 {
		reported := make([]map[string]any, 0, len(conflicts))
		for _, conflict := range conflicts {
			reported = append(reported, map[string]any{
				"bridge":        conflict.Bridge,
				"address":       conflict.Address,
				"local_mac":     conflict.LocalHardwareAddr,
				"responder_mac": conflict.ResponderHardwareAddr,
				"detected_at":   conflict.DetectedAt.Format(time.RFC3339),
			})
		}
		componentHealth.Details["conflicts"] = reported
		messages = append(messages, AddressConflictMessage+": "+conflictSummary(conflicts))
	}

	if len(unavailable) > 0 {
		reported := make([]map[string]any, 0, len(unavailable))
		for _, failure := range unavailable {
			reported = append(reported, map[string]any{
				"bridge":      failure.Bridge,
				"address":     failure.Address,
				"cause":       failure.Cause,
				"detected_at": failure.DetectedAt.Format(time.RFC3339),
			})
		}
		componentHealth.Details["probe_unavailable"] = reported
		messages = append(messages, ProbeUnavailableMessage+": "+unavailableSummary(unavailable))
	}

	componentHealth.Status = health.StatusDegraded
	componentHealth.Message = strings.Join(messages, "; ")
	componentHealth.Duration = time.Since(start)
	return componentHealth
}

// conflictSummary renders the operator-facing one-liner carried in the health
// message.
func conflictSummary(conflicts []app.BridgeAddressConflict) string {
	first := conflicts[0]
	summary := fmt.Sprintf("%s not assigned to %s, %s already answers for it",
		first.Address, first.Bridge, first.ResponderHardwareAddr)
	if len(conflicts) > 1 {
		summary += fmt.Sprintf(" (and %d more)", len(conflicts)-1)
	}
	return summary
}

// unavailableSummary renders the one-liner for addresses that went onto the
// wire without being probed. It names the cause, because that is what the
// operator has to fix.
func unavailableSummary(unavailable []app.BridgeAddressProbeUnavailable) string {
	first := unavailable[0]
	summary := fmt.Sprintf("%s assigned to %s unguarded: %s",
		first.Address, first.Bridge, first.Cause)
	if len(unavailable) > 1 {
		summary += fmt.Sprintf(" (and %d more)", len(unavailable)-1)
	}
	return summary
}
