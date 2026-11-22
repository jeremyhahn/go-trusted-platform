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

package tunnel

import (
	"errors"
	"fmt"
	"log/slog"

	vnl "github.com/vishvananda/netlink"
)

// RemoveStaleWireGuardHub deletes a WireGuard device named name that a
// predecessor left in the kernel, with every peer on it. A datapath that
// restarts with no hub to bring up calls it, since no hub's Up will. A
// device of another type is not a hub's and is left in place; no device is
// not an error.
//
// It is deletion only, with no WireGuard cryptography, so it is built in
// every build: a FIPS gatewayd that replaces a non-FIPS one after an
// ungraceful exit removes the hub the kernel still holds.
func RemoveStaleWireGuardHub(logger *slog.Logger, name string) error {
	return removeStaleWireGuardHub(logger, &realNetlinkOps{}, name)
}

func removeStaleWireGuardHub(logger *slog.Logger, nl netlinkOps, name string) error {
	stale, err := nl.LinkByName(name)
	if err != nil {
		// Only the typed not-found result proves the device absent; any other
		// lookup failure leaves a predecessor's hub possibly live.
		var missing vnl.LinkNotFoundError
		if errors.As(err, &missing) {
			return nil
		}
		return &ErrTunnelRemoveFailed{Name: name, Cause: fmt.Errorf("looking up a stale hub device: %w", err)}
	}
	if stale == nil || stale.Type() != (&vnl.Wireguard{}).Type() {
		return nil
	}
	if err := nl.LinkDel(stale); err != nil {
		return &ErrTunnelRemoveFailed{Name: name, Cause: fmt.Errorf("removing the stale hub device: %w", err)}
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("wireguard hub removed a stale device of its name", slog.String("device", name))
	return nil
}
