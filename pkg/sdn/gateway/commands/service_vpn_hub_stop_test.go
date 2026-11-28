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

//go:build !fips

package commands

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stopFailingPlane is a fake WireGuard plane whose Stop fails after
// recording the stop, as a hub whose link delete was refused.
type stopFailingPlane struct {
	*fakeVPNPlane
	err error
}

func (p stopFailingPlane) Stop(ctx context.Context) error {
	_ = p.fakeVPNPlane.Stop(ctx)
	return p.err
}

// A failed plane stop may leave the hub's device and kernel peers up, so
// the tp_vpn_hub table, with its closing drop and lease accepts, stays
// until a stop succeeds (#2093).
func TestHubNetworkPlane_AFailedStopKeepsTheEnforcement(t *testing.T) {
	ctx := context.Background()
	conn := &recordingHubConn{}
	plane, inner := hubPlaneWithFilter(conn)
	require.NoError(t, plane.InstallPeer(ctx, hubLease("a", "10.99.0.7/32")))

	errLinkDel := errors.New("link delete refused")
	failing := plane
	failing.ManagedDataPlane = stopFailingPlane{fakeVPNPlane: inner, err: errLinkDel}
	err := failing.Stop(ctx)
	require.ErrorIs(t, err, errLinkDel)
	assert.Empty(t, conn.deleted, "the hub's device may still be up, so its enforcement stays")

	require.NoError(t, plane.Stop(ctx))
	assert.Equal(t, []string{"tp_vpn_hub"}, conn.deleted, "a clean stop deletes the table")
}
