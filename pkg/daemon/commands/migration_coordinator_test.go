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
	"crypto/tls"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// fakePeer implements migrationPeer, recording requests and returning scripted
// responses so the coordinator can be driven without a network.
type fakePeer struct {
	prepResp *platformv1.PrepareMigrationResponse
	prepErr  error
	finResp  *platformv1.FinalizeMigrationResponse
	finErr   error

	lastPrep *platformv1.PrepareMigrationRequest
	lastFin  *platformv1.FinalizeMigrationRequest
	closed   bool
}

func (f *fakePeer) PrepareMigration(_ context.Context, in *platformv1.PrepareMigrationRequest, _ ...grpc.CallOption) (*platformv1.PrepareMigrationResponse, error) {
	f.lastPrep = in
	return f.prepResp, f.prepErr
}

func (f *fakePeer) FinalizeMigration(_ context.Context, in *platformv1.FinalizeMigrationRequest, _ ...grpc.CallOption) (*platformv1.FinalizeMigrationResponse, error) {
	f.lastFin = in
	return f.finResp, f.finErr
}

// coordinatorWith builds a coordinator whose TLS + dial seams are injected so no
// CA or network is required. dialCount is incremented on each newPeer call.
func coordinatorWith(peer *fakePeer, dialCount *int) *grpcMigrationCoordinator {
	return &grpcMigrationCoordinator{
		tlsConfigFor: func(context.Context) (*tls.Config, error) { return &tls.Config{}, nil },
		newPeer: func(context.Context, string, *tls.Config) (migrationPeer, func() error, error) {
			if dialCount != nil {
				*dialCount++
			}
			return peer, func() error { peer.closed = true; return nil }, nil
		},
		logger:  logging.DefaultLogger(),
		pending: make(map[string]string),
	}
}

func okStatus() *platformv1.Status { return &platformv1.Status{Success: true} }

func TestCoordinator_PrepareIncoming_HappyPath(t *testing.T) {
	peer := &fakePeer{prepResp: &platformv1.PrepareMigrationResponse{
		Status:      okStatus(),
		ReceiverId:  "recv-1",
		Port:        49200,
		TlsHostname: "dest.example",
	}}
	coord := coordinatorWith(peer, nil)

	spec := compute.MigrationSpec{
		InstanceID: "vm-1",
		VMName:     "guest",
		Mode:       compute.MigrateModeCold,
		Config:     &compute.InstanceConfig{Memory: 2048, CPUs: 2, TPMEnabled: true, MACAddress: "aa:bb"},
	}
	endpoint, err := coord.PrepareIncoming(context.Background(), "dest.example:10443", spec)
	require.NoError(t, err)
	assert.Equal(t, "tcp:dest.example:49200", endpoint.URI)
	assert.Equal(t, "dest.example", endpoint.TLSHostname)

	// Request fields are mapped.
	require.NotNil(t, peer.lastPrep)
	assert.Equal(t, "vm-1", peer.lastPrep.GetVmId())
	assert.Equal(t, "guest", peer.lastPrep.GetVmName())
	assert.Equal(t, "cold", peer.lastPrep.GetMode())
	require.NotNil(t, peer.lastPrep.GetSpec())
	assert.Equal(t, int32(2048), peer.lastPrep.GetSpec().GetMemoryMb())
	assert.True(t, peer.lastPrep.GetSpec().GetTpmEnabled())

	// The receiver token is retained for a later finalize.
	coord.mu.Lock()
	got := coord.pending[pendingKey("dest.example:10443", "vm-1")]
	coord.mu.Unlock()
	assert.Equal(t, "recv-1", got)
	assert.True(t, peer.closed, "connection closed after prepare")
}

func TestCoordinator_PrepareIncoming_BadDestination(t *testing.T) {
	coord := coordinatorWith(&fakePeer{}, nil)
	_, err := coord.PrepareIncoming(context.Background(), "no-port-here", compute.MigrationSpec{InstanceID: "vm-1"})
	require.Error(t, err)
	var peerErr *ErrMigrationPeer
	require.True(t, errors.As(err, &peerErr))
}

func TestCoordinator_PrepareIncoming_PeerError(t *testing.T) {
	peer := &fakePeer{prepErr: errors.New("unavailable")}
	coord := coordinatorWith(peer, nil)
	_, err := coord.PrepareIncoming(context.Background(), "dest.example:10443", compute.MigrationSpec{InstanceID: "vm-1"})
	require.Error(t, err)
	var peerErr *ErrMigrationPeer
	require.True(t, errors.As(err, &peerErr))
	assert.Equal(t, "PrepareMigration", peerErr.Op)
}

func TestCoordinator_PrepareIncoming_Rejected(t *testing.T) {
	peer := &fakePeer{prepResp: &platformv1.PrepareMigrationResponse{
		Status: &platformv1.Status{Success: false, Message: "no capacity"},
	}}
	coord := coordinatorWith(peer, nil)
	_, err := coord.PrepareIncoming(context.Background(), "dest.example:10443", compute.MigrationSpec{InstanceID: "vm-1"})
	require.Error(t, err)
	var rejErr *ErrMigrationPeerRejected
	require.True(t, errors.As(err, &rejErr))
	assert.Contains(t, rejErr.Message, "no capacity")
}

func TestCoordinator_Finalize_Commit(t *testing.T) {
	peer := &fakePeer{
		prepResp: &platformv1.PrepareMigrationResponse{Status: okStatus(), ReceiverId: "recv-1", Port: 5000},
		finResp:  &platformv1.FinalizeMigrationResponse{Status: okStatus()},
	}
	coord := coordinatorWith(peer, nil)
	spec := compute.MigrationSpec{InstanceID: "vm-1", VMName: "guest"}

	_, err := coord.PrepareIncoming(context.Background(), "dest.example:10443", spec)
	require.NoError(t, err)

	require.NoError(t, coord.Finalize(context.Background(), "dest.example:10443", spec, nil))
	require.NotNil(t, peer.lastFin)
	assert.Equal(t, "recv-1", peer.lastFin.GetReceiverId())
	assert.True(t, peer.lastFin.GetCommit(), "nil stream error commits")

	// The pending entry is consumed.
	coord.mu.Lock()
	_, exists := coord.pending[pendingKey("dest.example:10443", "vm-1")]
	coord.mu.Unlock()
	assert.False(t, exists)
}

func TestCoordinator_Finalize_Abort(t *testing.T) {
	peer := &fakePeer{
		prepResp: &platformv1.PrepareMigrationResponse{Status: okStatus(), ReceiverId: "recv-1"},
		finResp:  &platformv1.FinalizeMigrationResponse{Status: okStatus()},
	}
	coord := coordinatorWith(peer, nil)
	spec := compute.MigrationSpec{InstanceID: "vm-1"}

	_, err := coord.PrepareIncoming(context.Background(), "dest.example:10443", spec)
	require.NoError(t, err)

	require.NoError(t, coord.Finalize(context.Background(), "dest.example:10443", spec, errors.New("stream failed")))
	require.NotNil(t, peer.lastFin)
	assert.False(t, peer.lastFin.GetCommit(), "stream error aborts")
}

func TestCoordinator_Finalize_WithoutPrepareIsNoOp(t *testing.T) {
	dialCount := 0
	peer := &fakePeer{}
	coord := coordinatorWith(peer, &dialCount)

	// No PrepareIncoming was called, so Finalize has no receiver to reference.
	require.NoError(t, coord.Finalize(context.Background(), "dest.example:10443", compute.MigrationSpec{InstanceID: "vm-1"}, nil))
	assert.Equal(t, 0, dialCount, "no dial without a pending receiver")
	assert.Nil(t, peer.lastFin)
}

func TestNewGRPCMigrationCoordinator_NilCA(t *testing.T) {
	require.Nil(t, newGRPCMigrationCoordinator(nil, logging.DefaultLogger()))
}

func TestNewGRPCMigrationCoordinator_BuildsTLSFromCA(t *testing.T) {
	coord := newGRPCMigrationCoordinator(&fakeCAIssuer{}, logging.DefaultLogger())
	require.NotNil(t, coord)
	cfg, err := coord.tlsConfigFor(context.Background())
	require.NoError(t, err)
	require.Len(t, cfg.Certificates, 1)
	require.NotNil(t, cfg.RootCAs)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
}

func TestNewMigrationClientTLSConfig_IssueError(t *testing.T) {
	_, err := newMigrationClientTLSConfig(context.Background(), &fakeCAIssuer{issueErr: errors.New("ca down")})
	require.Error(t, err)
	var issueErr *ErrMigrationTLSIssue
	require.True(t, errors.As(err, &issueErr))
}

func TestNewMigrationClientTLSConfig_NilCA(t *testing.T) {
	_, err := newMigrationClientTLSConfig(context.Background(), nil)
	require.ErrorIs(t, err, ErrMigrationTLSNoCA{})
}

func TestToProtoMigrationSpec(t *testing.T) {
	assert.Nil(t, toProtoMigrationSpec(nil))

	got := toProtoMigrationSpec(&compute.InstanceConfig{
		Memory: 4096, CPUs: 4, DiskSize: "40G", BootMode: "boot",
		SecureBoot: true, EnableKVM: true, TPMEnabled: true,
		NetworkMode: "bridge", MACAddress: "52:54:00:aa:bb:cc",
	})
	require.NotNil(t, got)
	assert.Equal(t, int32(4096), got.GetMemoryMb())
	assert.Equal(t, int32(4), got.GetCpus())
	assert.Equal(t, "40G", got.GetDiskSize())
	assert.True(t, got.GetSecureBoot())
	assert.True(t, got.GetEnableKvm())
	assert.Equal(t, "52:54:00:aa:bb:cc", got.GetMacAddress())
}
