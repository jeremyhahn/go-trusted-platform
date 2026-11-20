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
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
)

// vpnHubInterface is the WireGuard hub's interface name in the datapath
// child.
const vpnHubInterface = "vpn-hub0"

// removeStaleWireGuardDevice deletes a stale WireGuard device by name; a
// variable so a test can observe the call.
var removeStaleWireGuardDevice = tunnel.RemoveStaleWireGuardHub

// removeStaleVPNHub removes the hub device of vpnHubInterface a killed
// predecessor left in the kernel, for a datapath that builds no plane. It is
// built in every build: a FIPS gatewayd creates no WireGuard hub, but one
// that replaces a non-FIPS gatewayd after an ungraceful exit still removes
// the hub, and its peers, that the kernel holds.
func removeStaleVPNHub(logger *slog.Logger) error {
	return removeStaleWireGuardDevice(logger, vpnHubInterface)
}
