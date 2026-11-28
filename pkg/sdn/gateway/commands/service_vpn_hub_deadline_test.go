// Copyright (c) 2026 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

//go:build !fips

package commands

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// A hub peer hosted in the datapath loses its forwarding accepts once its
// lease deadline passes, through the plane host alone: no admission
// service, no sweep.
func TestHubLeaseDeadline_AHostedPeerPastItsDeadlineLosesItsAccepts(t *testing.T) {
	ctx := context.Background()
	conn := &recordingHubConn{}
	plane, _ := hubPlaneWithFilter(conn)
	host, err := vpn.NewPlaneHost(plane)
	require.NoError(t, err)
	dp, err := vpn.NewDatapathPlane(vpn.DataPlaneMASQUE, wirePeers{host: host})
	require.NoError(t, err)

	lease := hubLease("a", "10.99.0.7/32")
	lease.ExpiresAt = time.Now().Add(time.Hour)
	require.NoError(t, dp.InstallPeer(ctx, lease))
	require.Equal(t, []string{"10.99.0.7->10.4.10.0"}, hubAccepts(conn.lastBatch()))

	require.NoError(t, host.ExpirePeers(ctx, lease.ExpiresAt.Add(-time.Second)))
	assert.Equal(t, []string{"10.99.0.7->10.4.10.0"}, hubAccepts(conn.lastBatch()))

	require.NoError(t, host.ExpirePeers(ctx, lease.ExpiresAt))
	assert.Empty(t, hubAccepts(conn.lastBatch()))
}

// The hub serves only leases with a deadline: the plane host enforces it.
func TestHubLeaseDeadline_ALeaseWithoutADeadlineIsRefused(t *testing.T) {
	conn := &recordingHubConn{}
	plane, inner := hubPlaneWithFilter(conn)

	lease := hubLease("a", "10.99.0.7/32")
	lease.ExpiresAt = time.Time{}
	err := plane.InstallPeer(context.Background(), lease)
	var invalid *vpn.ErrInvalidRequest
	require.True(t, errors.As(err, &invalid), "got %v", err)
	assert.Equal(t, "expires_at", invalid.Field)

	_, _, installed := inner.state()
	assert.Empty(t, installed)
	for _, batch := range conn.batches {
		assert.Empty(t, hubAccepts(batch))
	}
}
