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

package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/arp"
)

// BridgeAddressConflict records a bridge address the duplicate-address guard
// refused to assign because another station on the segment already answers
// for it. Both hardware addresses are kept so an operator can identify the
// other station without going back to the wire.
type BridgeAddressConflict struct {
	// Bridge is the OVS bridge whose address was refused.
	Bridge string

	// Address is the CIDR address from the node's network configuration.
	Address string

	// LocalHardwareAddr is the MAC of the bridge interface that probed.
	LocalHardwareAddr string

	// ResponderHardwareAddr is the MAC of the station that answered.
	ResponderHardwareAddr string

	// DetectedAt is when the conflict was detected.
	DetectedAt time.Time
}

// BridgeAddressProbeUnavailable records a bridge address that was assigned
// without being probed, because the probe itself could not run. The address
// is on the wire; what is missing is the evidence that it was free. A node in
// this state looks healthy from every other angle, which is exactly why it is
// recorded rather than only logged.
type BridgeAddressProbeUnavailable struct {
	// Bridge is the OVS bridge whose address went unguarded.
	Bridge string

	// Address is the CIDR address from the node's network configuration.
	Address string

	// Cause is why the probe could not run: no CAP_NET_RAW, an interface
	// that is not visible, an unsupported platform.
	Cause string

	// DetectedAt is when the probe failed.
	DetectedAt time.Time
}

// ErrBridgeAddressConflict is returned when the duplicate-address guard
// refuses a configured bridge address because another station on the segment
// already answers for it. This is the message an operator greps for: it names
// the address, the bridge, and both hardware addresses.
type ErrBridgeAddressConflict struct {
	// Conflict is the recorded conflict.
	Conflict BridgeAddressConflict

	// Cause is the underlying *arp.ConflictError.
	Cause error
}

// Error implements the error interface.
func (e ErrBridgeAddressConflict) Error() string {
	return fmt.Sprintf(
		"sdn: refusing to assign %s to bridge %s: %s already answers for that address on this segment (local %s)",
		e.Conflict.Address,
		e.Conflict.Bridge,
		e.Conflict.ResponderHardwareAddr,
		e.Conflict.LocalHardwareAddr,
	)
}

// Unwrap returns the underlying probe error.
func (e ErrBridgeAddressConflict) Unwrap() error { return e.Cause }

// bridgeAddressProbe is the duplicate-address check initBridgeIPs runs before
// assigning a bridge address. It is a package variable so tests exercise the
// guard entirely in memory: no test ever opens a raw socket or touches a
// network segment.
var bridgeAddressProbe = probeBridgeAddress

// probeBridgeAddress runs RFC 5227 duplicate-address detection for ip on
// iface using a raw ARP socket.
func probeBridgeAddress(ctx context.Context, iface string, ip net.IP) error {
	detector := arp.NewDuplicateAddressDetector(arp.NewRawProbeTransport())
	return detector.Check(ctx, iface, ip)
}

// guardBridgeAddress decides whether the platform may assign addr to bridge.
//
// It returns an error only when the address must not be assigned — that is,
// when another station defended it. A probe that could not be carried out
// (no CAP_NET_RAW, interface not yet visible, unsupported platform) is
// logged and permitted: refusing an address because the guard itself is
// unavailable would take a control plane offline over a diagnostic that said
// nothing about the segment. The refusal is reserved for a measured conflict.
func (app *App) guardBridgeAddress(ctx context.Context, bridge, addr string) error {
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		app.Logger.Warn("SDN: duplicate-address guard skipped, unparsable address",
			slog.String("bridge", bridge),
			slog.String("address", addr),
			slog.String("error", err.Error()))
		return nil
	}

	probeErr := bridgeAddressProbe(ctx, bridge, ip)
	if probeErr == nil {
		return nil
	}

	var conflict *arp.ConflictError
	if !errors.As(probeErr, &conflict) {
		app.recordBridgeAddressProbeUnavailable(BridgeAddressProbeUnavailable{
			Bridge:     bridge,
			Address:    addr,
			Cause:      probeErr.Error(),
			DetectedAt: time.Now().UTC(),
		})
		app.Logger.Warn("SDN: duplicate-address probe unavailable, assigning address unguarded",
			slog.String("bridge", bridge),
			slog.String("address", addr),
			slog.String("error", probeErr.Error()))
		return nil
	}

	record := BridgeAddressConflict{
		Bridge:                bridge,
		Address:               addr,
		LocalHardwareAddr:     conflict.LocalHardwareAddr.String(),
		ResponderHardwareAddr: conflict.ResponderHardwareAddr.String(),
		DetectedAt:            time.Now().UTC(),
	}
	app.recordBridgeAddressConflict(record)

	refusal := ErrBridgeAddressConflict{Conflict: record, Cause: conflict}
	app.Logger.Error(refusal,
		"bridge", bridge,
		"address", addr,
		"local_mac", record.LocalHardwareAddr,
		"responder_mac", record.ResponderHardwareAddr)

	return refusal
}

// bridgeAddressConflictLog holds what the duplicate-address guard learned
// during bring-up: the addresses it refused, and the addresses it could not
// probe. It lives behind a pointer on the App so the App itself stays
// copyable.
type bridgeAddressConflictLog struct {
	conflicts   []BridgeAddressConflict
	unavailable []BridgeAddressProbeUnavailable
}

// bridgeAddressLogMu serialises access to every App's conflict log — both the
// pointer on the App and the slice behind it. The lock cannot live on the App
// (see the field comment: App is copied by value), and a package-level lock
// costs nothing here: it is taken a handful of times at bring-up and once per
// health check, never on a data path.
var bridgeAddressLogMu sync.Mutex

// recordBridgeAddressConflict appends a conflict to the node's record. The
// same record backs the degraded health component and the platform event the
// daemon publishes once its transports are up.
func (app *App) recordBridgeAddressConflict(conflict BridgeAddressConflict) {
	bridgeAddressLogMu.Lock()
	defer bridgeAddressLogMu.Unlock()
	if app.bridgeAddressConflicts == nil {
		app.bridgeAddressConflicts = &bridgeAddressConflictLog{}
	}
	app.bridgeAddressConflicts.conflicts = append(app.bridgeAddressConflicts.conflicts, conflict)
}

// recordBridgeAddressProbeUnavailable appends an unguarded assignment to the
// node's record, so a node that quietly lost the guard reports degraded
// instead of looking healthy.
func (app *App) recordBridgeAddressProbeUnavailable(unavailable BridgeAddressProbeUnavailable) {
	bridgeAddressLogMu.Lock()
	defer bridgeAddressLogMu.Unlock()
	if app.bridgeAddressConflicts == nil {
		app.bridgeAddressConflicts = &bridgeAddressConflictLog{}
	}
	app.bridgeAddressConflicts.unavailable = append(app.bridgeAddressConflicts.unavailable, unavailable)
}

// BridgeAddressConflicts returns the bridge addresses this node refused to
// assign because another station already answered for them. An empty result
// means the guard found no conflict.
func (app *App) BridgeAddressConflicts() []BridgeAddressConflict {
	if app == nil {
		return nil
	}
	bridgeAddressLogMu.Lock()
	defer bridgeAddressLogMu.Unlock()
	log := app.bridgeAddressConflicts
	if log == nil || len(log.conflicts) == 0 {
		return nil
	}
	return append([]BridgeAddressConflict(nil), log.conflicts...)
}

// BridgeAddressProbeFailures returns the bridge addresses this node assigned
// without probing, because the probe could not run. An empty result means
// every configured address was actually guarded.
func (app *App) BridgeAddressProbeFailures() []BridgeAddressProbeUnavailable {
	if app == nil {
		return nil
	}
	bridgeAddressLogMu.Lock()
	defer bridgeAddressLogMu.Unlock()
	log := app.bridgeAddressConflicts
	if log == nil || len(log.unavailable) == 0 {
		return nil
	}
	return append([]BridgeAddressProbeUnavailable(nil), log.unavailable...)
}
