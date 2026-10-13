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
	"errors"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vpn"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// vpnTestPolicy is a posture policy module that compiles.
const vpnTestPolicy = `package vpn.posture

import rego.v1

default allow := false

allow if input.posture.agent_version == "9.9.9"
`

// vpnTestSnapshots is an in-memory gateway telemetry store.
type vpnTestSnapshots struct {
	snaps map[string]*gwstate.Snapshot
	err   error
}

func (s *vpnTestSnapshots) Put(snap *gwstate.Snapshot) error {
	s.snaps[snap.GatewayID] = snap
	return nil
}

func (s *vpnTestSnapshots) Get(id string) (*gwstate.Snapshot, error) {
	if s.err != nil {
		return nil, s.err
	}
	snap, ok := s.snaps[id]
	if !ok {
		return nil, gwstate.ErrSnapshotNotFound{GatewayID: id}
	}
	return snap, nil
}

func (s *vpnTestSnapshots) List() ([]*gwstate.Snapshot, error) {
	if s.err != nil {
		return nil, s.err
	}
	out := make([]*gwstate.Snapshot, 0, len(s.snaps))
	for _, snap := range s.snaps {
		out = append(out, snap)
	}
	return out, nil
}

func (s *vpnTestSnapshots) Delete(id string) error {
	delete(s.snaps, id)
	return nil
}

// newVPNTestServer builds the gRPC service over a real VPN control plane on
// in-memory storage, with a telemetry store holding one VPN gateway and one
// gateway that runs no VPN service.
func newVPNTestServer(t *testing.T) (*VPNGRPCService, *quicbaas.MockStorage) {
	t.Helper()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	controlPlane, err := vpn.NewService(storage, logging.DefaultLogger())
	require.NoError(t, err)

	reported := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	controlPlane.SetGatewaySnapshotStore(&vpnTestSnapshots{snaps: map[string]*gwstate.Snapshot{
		"gw-1": {
			GatewayID:  "gw-1",
			ReportedAt: reported,
			VPN: &gwstate.VPNState{
				Running:           true,
				Admissions:        7,
				Refusals:          2,
				LastRefusal:       "peer not enrolled",
				EnrolledPeers:     3,
				LeasesByDataPlane: map[string]int{"masque": 1},
				Leases: []gwstate.VPNLeaseState{{
					ID: "lease-1", TenantID: "acme", DeviceID: "laptop-1", Address: "10.99.0.2",
					DataPlane: "masque", Zones: []string{"management"},
					IssuedAt: reported, ExpiresAt: reported.Add(time.Hour), Renewals: 4,
				}},
				PosturePolicyErrors: []string{"globex/corp: compile failed"},
				RejectedPeers: []gwstate.VPNRejectedPeer{
					{TenantID: "acme", DeviceID: "laptop-9", Reason: `zone "storage" is not reachable`},
				},
			},
		},
		"gw-2": {GatewayID: "gw-2", ReportedAt: reported},
	}})
	return NewVPNGRPCService(logging.DefaultLogger(), controlPlane), storage
}

func TestVPNGRPCService_PeerLifecycle(t *testing.T) {
	server, _ := newVPNTestServer(t)
	ctx := context.Background()

	enrolled, err := server.EnrolPeer(ctx, &platformv1.EnrolVPNPeerRequest{
		Peer: &platformv1.VPNPeer{TenantId: "acme", DeviceId: "laptop-1", Zones: []string{"management"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "laptop-1", enrolled.GetPeer().GetDeviceId())
	assert.Equal(t, []string{"management"}, enrolled.GetPeer().GetZones())
	assert.NotZero(t, enrolled.GetPeer().GetEnrolledAtUnix())

	_, err = server.EnrolPeer(ctx, &platformv1.EnrolVPNPeerRequest{
		Peer: &platformv1.VPNPeer{TenantId: "globex", DeviceId: "phone-1"},
	})
	require.NoError(t, err)

	listed, err := server.ListPeers(ctx, &platformv1.ListVPNPeersRequest{TenantId: "acme"})
	require.NoError(t, err)
	require.Len(t, listed.GetPeers(), 1, "the tenant filter must hide other tenants' peers")

	_, err = server.RevokePeer(ctx, &platformv1.RevokeVPNPeerRequest{TenantId: "acme", DeviceId: "laptop-1"})
	require.NoError(t, err)

	_, err = server.RevokePeer(ctx, &platformv1.RevokeVPNPeerRequest{TenantId: "acme", DeviceId: "laptop-1"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestVPNGRPCService_PosturePolicyLifecycle(t *testing.T) {
	server, _ := newVPNTestServer(t)
	ctx := context.Background()

	set, err := server.SetPosturePolicy(ctx, &platformv1.SetVPNPosturePolicyRequest{
		Policy: &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp", Module: vpnTestPolicy},
	})
	require.NoError(t, err)
	assert.NotZero(t, set.GetPolicy().GetUpdatedAtUnix())

	got, err := server.GetPosturePolicy(ctx, &platformv1.GetVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"})
	require.NoError(t, err)
	assert.Equal(t, vpnTestPolicy, got.GetPolicy().GetModule())

	listed, err := server.ListPosturePolicies(ctx, &platformv1.ListVPNPosturePoliciesRequest{})
	require.NoError(t, err)
	assert.Len(t, listed.GetPolicies(), 1)

	_, err = server.DeletePosturePolicy(ctx, &platformv1.DeleteVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"})
	require.NoError(t, err)

	_, err = server.GetPosturePolicy(ctx, &platformv1.GetVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestVPNGRPCService_RefusesInvalidRequests(t *testing.T) {
	server, _ := newVPNTestServer(t)
	ctx := context.Background()

	_, err := server.EnrolPeer(ctx, &platformv1.EnrolVPNPeerRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a missing peer")

	_, err = server.EnrolPeer(ctx, &platformv1.EnrolVPNPeerRequest{Peer: &platformv1.VPNPeer{TenantId: "acme"}})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a missing device id")

	_, err = server.SetPosturePolicy(ctx, &platformv1.SetVPNPosturePolicyRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a missing policy")

	_, err = server.SetPosturePolicy(ctx, &platformv1.SetVPNPosturePolicyRequest{
		Policy: &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp", Module: "package other\n"},
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a module outside package vpn.posture")

	listed, err := server.ListPosturePolicies(ctx, &platformv1.ListVPNPosturePoliciesRequest{})
	require.NoError(t, err)
	assert.Empty(t, listed.GetPolicies(), "a refused policy must not be stored")
}

func TestVPNGRPCService_StoreFailureIsUnavailable(t *testing.T) {
	server, storage := newVPNTestServer(t)
	storage.ListError = errors.New("raft leader lost")

	_, err := server.ListPeers(context.Background(), &platformv1.ListVPNPeersRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestVPNGRPCService_GetStatusReportsGatewayTelemetry(t *testing.T) {
	server, _ := newVPNTestServer(t)
	ctx := context.Background()

	resp, err := server.GetStatus(ctx, &platformv1.GetVPNStatusRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetGateways(), 2)

	vpnGateway := resp.GetGateways()[0]
	assert.Equal(t, "gw-1", vpnGateway.GetGatewayId())
	assert.True(t, vpnGateway.GetReporting())
	assert.True(t, vpnGateway.GetRunning())
	assert.Equal(t, uint64(7), vpnGateway.GetAdmissions())
	assert.Equal(t, uint64(2), vpnGateway.GetRefusals())
	assert.Equal(t, uint32(3), vpnGateway.GetEnrolledPeers())
	assert.Equal(t, map[string]uint32{"masque": 1}, vpnGateway.GetLeasesByDataPlane())
	require.Len(t, vpnGateway.GetLeases(), 1)
	assert.Equal(t, "10.99.0.2", vpnGateway.GetLeases()[0].GetAddress())
	assert.Equal(t, uint32(4), vpnGateway.GetLeases()[0].GetRenewals())
	assert.Equal(t, []string{"globex/corp: compile failed"}, vpnGateway.GetPosturePolicyErrors())
	require.Len(t, vpnGateway.GetRejectedPeers(), 1, "a refused peer is reported with its gateway")
	assert.Equal(t, "acme", vpnGateway.GetRejectedPeers()[0].GetTenantId())
	assert.Equal(t, "laptop-9", vpnGateway.GetRejectedPeers()[0].GetDeviceId())
	assert.Equal(t, `zone "storage" is not reachable`, vpnGateway.GetRejectedPeers()[0].GetReason())

	plainGateway := resp.GetGateways()[1]
	assert.False(t, plainGateway.GetReporting(), "a gateway without a VPN section is not reporting")
	assert.Empty(t, plainGateway.GetLeases())

	_, err = server.GetStatus(ctx, &platformv1.GetVPNStatusRequest{GatewayId: "gw-missing"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestVPNGRPCService_GetStatusWithoutTelemetryIsUnavailable(t *testing.T) {
	server, _ := newVPNTestServer(t)
	server.Backend().(*vpn.Service).SetGatewaySnapshotStore(nil)

	_, err := server.GetStatus(context.Background(), &platformv1.GetVPNStatusRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestVPNGRPCService_WithoutBackendEveryRPCIsUnavailable(t *testing.T) {
	server := NewVPNGRPCService(nil, nil)
	ctx := context.Background()

	calls := map[string]func() error{
		"EnrolPeer": func() error {
			_, err := server.EnrolPeer(ctx, &platformv1.EnrolVPNPeerRequest{})
			return err
		},
		"ListPeers": func() error {
			_, err := server.ListPeers(ctx, &platformv1.ListVPNPeersRequest{})
			return err
		},
		"RevokePeer": func() error {
			_, err := server.RevokePeer(ctx, &platformv1.RevokeVPNPeerRequest{})
			return err
		},
		"GetStatus": func() error {
			_, err := server.GetStatus(ctx, &platformv1.GetVPNStatusRequest{})
			return err
		},
		"GetPosturePolicy": func() error {
			_, err := server.GetPosturePolicy(ctx, &platformv1.GetVPNPosturePolicyRequest{})
			return err
		},
		"SetPosturePolicy": func() error {
			_, err := server.SetPosturePolicy(ctx, &platformv1.SetVPNPosturePolicyRequest{})
			return err
		},
		"DeletePosturePolicy": func() error {
			_, err := server.DeletePosturePolicy(ctx, &platformv1.DeleteVPNPosturePolicyRequest{})
			return err
		},
		"ListPosturePolicies": func() error {
			_, err := server.ListPosturePolicies(ctx, &platformv1.ListVPNPosturePoliciesRequest{})
			return err
		},
	}
	for name, call := range calls {
		assert.Equal(t, codes.Unavailable, status.Code(call()), name)
	}
}

// vpnServiceErrorCases pins the failure class each pkg/vpn error takes on
// the gRPC surface and on the QUIC wire, so the two cannot drift apart. A
// cancelled call has no QUIC status of its own: its caller has gone, and
// nothing reads the answer.
var vpnServiceErrorCases = []struct {
	err  error
	grpc codes.Code
	quic byte
}{
	{&vpn.ErrInvalidArgument{Field: "tenant_id", Reason: "required"}, codes.InvalidArgument, quicwire.StatusInvalidArgument},
	{&vpn.ErrInvalidPosturePolicy{TenantID: "acme", Name: "corp", Reason: "parse"}, codes.InvalidArgument, quicwire.StatusInvalidArgument},
	{&vpn.ErrPeerNotFound{TenantID: "acme", DeviceID: "d"}, codes.NotFound, quicwire.StatusNotFound},
	{&vpn.ErrPosturePolicyNotFound{TenantID: "acme", Name: "corp"}, codes.NotFound, quicwire.StatusNotFound},
	{&vpn.ErrGatewayNotFound{GatewayID: "gw"}, codes.NotFound, quicwire.StatusNotFound},
	{&vpn.ErrKeyCollision{Kind: "peer", Key: "a", Stored: "b"}, codes.Aborted, quicwire.StatusAlreadyExists},
	{&vpn.ErrStoreUnavailable{Op: "list", Cause: errors.New("down")}, codes.Unavailable, quicwire.StatusUnavailable},
	{&vpn.ErrPolicyEngineUnavailable{Cause: errors.New("down")}, codes.Unavailable, quicwire.StatusUnavailable},
	{&vpn.ErrStatusUnavailable{Reason: "no store"}, codes.Unavailable, quicwire.StatusUnavailable},
	{context.Canceled, codes.Canceled, quicwire.StatusInternalError},
	{context.DeadlineExceeded, codes.DeadlineExceeded, quicwire.StatusTimeout},
	{errors.New("unexpected"), codes.Internal, quicwire.StatusInternalError},
}

func TestVPNErrToGRPC_MapsEveryTypedError(t *testing.T) {
	for _, tc := range vpnServiceErrorCases {
		assert.Equal(t, tc.grpc, status.Code(vpnErrToGRPC(tc.err)), "%T", tc.err)
	}
}

func TestClampUint32(t *testing.T) {
	assert.Equal(t, uint32(5), clampUint32(5))
	assert.Equal(t, uint32(0), clampUint32(-1), "a negative count clamps to zero")
	assert.Equal(t, uint32(math.MaxUint32), clampUint32(math.MaxInt), "an overflowing count saturates")
}

func TestBuildVPNControlPlane(t *testing.T) {
	assert.Nil(t, buildVPNControlPlane(nil, logging.DefaultLogger()), "no config means no control plane")
	assert.Nil(t, buildVPNControlPlane(&Config{}, logging.DefaultLogger()), "no platform storage means no control plane")
}
