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
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRemoveStaleVPNHub_RemovesTheHubInEveryBuild covers a FIPS gatewayd
// that replaces a non-FIPS one after an ungraceful exit, without a reboot:
// the kernel still holds vpn-hub0 and its peers, so the FIPS datapath child,
// which hosts no WireGuard plane, deletes that device as the non-FIPS one
// does, and a failed deletion stops it.
func TestRemoveStaleVPNHub_RemovesTheHubInEveryBuild(t *testing.T) {
	prev := removeStaleWireGuardDevice
	t.Cleanup(func() { removeStaleWireGuardDevice = prev })

	var removed []string
	removeStaleWireGuardDevice = func(_ *slog.Logger, name string) error {
		removed = append(removed, name)
		return nil
	}
	require.NoError(t, removeStaleVPNHub(testLogger()))
	require.Equal(t, []string{vpnHubInterface}, removed)

	boom := errors.New("netlink: operation not permitted")
	removeStaleWireGuardDevice = func(*slog.Logger, string) error { return boom }
	require.ErrorIs(t, removeStaleVPNHub(testLogger()), boom)
}
