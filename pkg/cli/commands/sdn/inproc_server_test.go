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

package sdn

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil/socktest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errBackendDown is the failure the in-process services return once a
// test sets recorder.fail.
var errBackendDown = status.Error(codes.Internal, "backend down")

// recorder is the state the in-process SDN, Gateway and Overlay services
// share: the last request each RPC received, the reply a test configured,
// and an optional failure every RPC returns instead.
type recorder struct {
	mu        sync.Mutex
	fail      error
	failures  map[string]error
	requests  map[string]proto.Message
	responses map[string]proto.Message
}

// reply records req under method and returns the configured response, the
// configured failure, or empty when the test configured neither.
func reply[Resp proto.Message](r *recorder, method string, req proto.Message, empty Resp) (Resp, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests[method] = req
	if err := r.failures[method]; err != nil {
		var zero Resp
		return zero, err
	}
	if r.fail != nil {
		var zero Resp
		return zero, r.fail
	}
	if resp, ok := r.responses[method]; ok {
		return resp.(Resp), nil
	}
	return empty, nil
}

// respond configures the reply method returns.
func (r *recorder) respond(method string, resp proto.Message) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.responses[method] = resp
}

// failWith makes every RPC return err.
func (r *recorder) failWith(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fail = err
}

// failOn makes only the named method return err.
func (r *recorder) failOn(method string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures[method] = err
}

// request returns the last request method received, failing the test when
// the CLI never called it.
func (r *recorder) request(t *testing.T, method string) proto.Message {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	req, ok := r.requests[method]
	require.True(t, ok, "%s was never called", method)
	return req
}

// startSDNServer serves the SDN, Gateway and Overlay services in-process on
// a unix socket and returns flags whose local context dials it, so the run
// functions execute their real SDK client path end to end.
func startSDNServer(t *testing.T, format cli.OutputFormat) (*recorder, *cli.CommonFlags) {
	t.Helper()
	sock := filepath.Join(socktest.Dir(t), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)

	rec := &recorder{
		failures:  map[string]error{},
		requests:  map[string]proto.Message{},
		responses: map[string]proto.Message{},
	}
	gs := grpc.NewServer()
	platformv1.RegisterSDNServiceServer(gs, &fakeSDN{rec: rec})
	platformv1.RegisterGatewayServiceServer(gs, &fakeGateway{rec: rec})
	platformv1.RegisterOverlayServiceServer(gs, &fakeOverlay{rec: rec})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	flags := &cli.CommonFlags{
		OutputFormat: format,
		NoColor:      true,
		GetContext: func() (*cli.Context, error) {
			return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
		},
	}
	return rec, flags
}

// captureStdout runs fn with os.Stdout redirected and returns what it
// printed alongside its error.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w

	done := make(chan []byte)
	go func() {
		out, _ := io.ReadAll(r)
		done <- out
	}()

	runErr := fn()
	os.Stdout = orig
	require.NoError(t, w.Close())
	out := <-done
	require.NoError(t, r.Close())
	return string(out), runErr
}

type fakeSDN struct {
	platformv1.UnimplementedSDNServiceServer
	rec *recorder
}

func (s *fakeSDN) CreateBridge(_ context.Context, req *platformv1.CreateBridgeRequest) (*platformv1.CreateBridgeResponse, error) {
	return reply(s.rec, "CreateBridge", req, &platformv1.CreateBridgeResponse{})
}

func (s *fakeSDN) DeleteBridge(_ context.Context, req *platformv1.DeleteBridgeRequest) (*platformv1.DeleteBridgeResponse, error) {
	return reply(s.rec, "DeleteBridge", req, &platformv1.DeleteBridgeResponse{})
}

func (s *fakeSDN) GetBridge(_ context.Context, req *platformv1.GetBridgeRequest) (*platformv1.GetBridgeResponse, error) {
	return reply(s.rec, "GetBridge", req, &platformv1.GetBridgeResponse{})
}

func (s *fakeSDN) ListBridges(_ context.Context, req *platformv1.ListBridgesRequest) (*platformv1.ListBridgesResponse, error) {
	return reply(s.rec, "ListBridges", req, &platformv1.ListBridgesResponse{})
}

func (s *fakeSDN) AddPort(_ context.Context, req *platformv1.AddPortRequest) (*platformv1.AddPortResponse, error) {
	return reply(s.rec, "AddPort", req, &platformv1.AddPortResponse{})
}

func (s *fakeSDN) DeletePort(_ context.Context, req *platformv1.DeletePortRequest) (*platformv1.DeletePortResponse, error) {
	return reply(s.rec, "DeletePort", req, &platformv1.DeletePortResponse{})
}

func (s *fakeSDN) GetPort(_ context.Context, req *platformv1.GetPortRequest) (*platformv1.GetPortResponse, error) {
	return reply(s.rec, "GetPort", req, &platformv1.GetPortResponse{})
}

func (s *fakeSDN) SetPortState(_ context.Context, req *platformv1.SetPortStateRequest) (*platformv1.SetPortStateResponse, error) {
	return reply(s.rec, "SetPortState", req, &platformv1.SetPortStateResponse{})
}

func (s *fakeSDN) GetPortStats(_ context.Context, req *platformv1.GetPortStatsRequest) (*platformv1.GetPortStatsResponse, error) {
	return reply(s.rec, "GetPortStats", req, &platformv1.GetPortStatsResponse{})
}

func (s *fakeSDN) AddFlow(_ context.Context, req *platformv1.AddFlowRequest) (*platformv1.AddFlowResponse, error) {
	return reply(s.rec, "AddFlow", req, &platformv1.AddFlowResponse{})
}

func (s *fakeSDN) DeleteFlow(_ context.Context, req *platformv1.DeleteFlowRequest) (*platformv1.DeleteFlowResponse, error) {
	return reply(s.rec, "DeleteFlow", req, &platformv1.DeleteFlowResponse{})
}

func (s *fakeSDN) ListFlows(_ context.Context, req *platformv1.ListFlowsRequest) (*platformv1.ListFlowsResponse, error) {
	return reply(s.rec, "ListFlows", req, &platformv1.ListFlowsResponse{})
}

func (s *fakeSDN) CreateVLAN(_ context.Context, req *platformv1.CreateVLANRequest) (*platformv1.CreateVLANResponse, error) {
	return reply(s.rec, "CreateVLAN", req, &platformv1.CreateVLANResponse{})
}

func (s *fakeSDN) DeleteVLAN(_ context.Context, req *platformv1.DeleteVLANRequest) (*platformv1.DeleteVLANResponse, error) {
	return reply(s.rec, "DeleteVLAN", req, &platformv1.DeleteVLANResponse{})
}

func (s *fakeSDN) ListVLANs(_ context.Context, req *platformv1.ListVLANsRequest) (*platformv1.ListVLANsResponse, error) {
	return reply(s.rec, "ListVLANs", req, &platformv1.ListVLANsResponse{})
}

func (s *fakeSDN) ApplyPolicy(_ context.Context, req *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error) {
	return reply(s.rec, "ApplyPolicy", req, &platformv1.ApplyPolicyResponse{})
}

func (s *fakeSDN) GetPolicy(_ context.Context, req *platformv1.GetPolicyRequest) (*platformv1.GetPolicyResponse, error) {
	return reply(s.rec, "GetPolicy", req, &platformv1.GetPolicyResponse{})
}

func (s *fakeSDN) ListPolicies(_ context.Context, req *platformv1.ListPoliciesRequest) (*platformv1.ListPoliciesResponse, error) {
	return reply(s.rec, "ListPolicies", req, &platformv1.ListPoliciesResponse{})
}

func (s *fakeSDN) CreateNetworkZone(_ context.Context, req *platformv1.CreateNetworkZoneRequest) (*platformv1.CreateNetworkZoneResponse, error) {
	return reply(s.rec, "CreateNetworkZone", req, &platformv1.CreateNetworkZoneResponse{})
}

func (s *fakeSDN) UpdateNetworkZone(_ context.Context, req *platformv1.UpdateNetworkZoneRequest) (*platformv1.UpdateNetworkZoneResponse, error) {
	return reply(s.rec, "UpdateNetworkZone", req, &platformv1.UpdateNetworkZoneResponse{})
}

func (s *fakeSDN) DeleteNetworkZone(_ context.Context, req *platformv1.DeleteNetworkZoneRequest) (*platformv1.DeleteNetworkZoneResponse, error) {
	return reply(s.rec, "DeleteNetworkZone", req, &platformv1.DeleteNetworkZoneResponse{})
}

func (s *fakeSDN) ListNetworkZones(_ context.Context, req *platformv1.ListNetworkZonesRequest) (*platformv1.ListNetworkZonesResponse, error) {
	return reply(s.rec, "ListNetworkZones", req, &platformv1.ListNetworkZonesResponse{})
}

type fakeGateway struct {
	platformv1.UnimplementedGatewayServiceServer
	rec *recorder
}

func (s *fakeGateway) GetGatewayStatus(_ context.Context, req *platformv1.GetGatewayStatusRequest) (*platformv1.GetGatewayStatusResponse, error) {
	return reply(s.rec, "GetGatewayStatus", req, &platformv1.GetGatewayStatusResponse{})
}

func (s *fakeGateway) SetGatewayMode(_ context.Context, req *platformv1.SetGatewayModeRequest) (*platformv1.SetGatewayModeResponse, error) {
	return reply(s.rec, "SetGatewayMode", req, &platformv1.SetGatewayModeResponse{})
}

func (s *fakeGateway) GetGatewaySnapshot(_ context.Context, req *platformv1.GetGatewaySnapshotRequest) (*platformv1.GetGatewaySnapshotResponse, error) {
	return reply(s.rec, "GetGatewaySnapshot", req, &platformv1.GetGatewaySnapshotResponse{})
}

func (s *fakeGateway) ListGatewaySnapshots(_ context.Context, req *platformv1.ListGatewaySnapshotsRequest) (*platformv1.ListGatewaySnapshotsResponse, error) {
	return reply(s.rec, "ListGatewaySnapshots", req, &platformv1.ListGatewaySnapshotsResponse{})
}

func (s *fakeGateway) GetGatewayAdmittedVTEP(_ context.Context, req *platformv1.GetGatewayAdmittedVTEPRequest) (*platformv1.GetGatewayAdmittedVTEPResponse, error) {
	return reply(s.rec, "GetGatewayAdmittedVTEP", req, &platformv1.GetGatewayAdmittedVTEPResponse{})
}

func (s *fakeGateway) ListGatewayAdmittedVTEPs(_ context.Context, req *platformv1.ListGatewayAdmittedVTEPsRequest) (*platformv1.ListGatewayAdmittedVTEPsResponse, error) {
	return reply(s.rec, "ListGatewayAdmittedVTEPs", req, &platformv1.ListGatewayAdmittedVTEPsResponse{})
}

func (s *fakeGateway) GetBGPStatus(_ context.Context, req *platformv1.GetBGPStatusRequest) (*platformv1.GetBGPStatusResponse, error) {
	return reply(s.rec, "GetBGPStatus", req, &platformv1.GetBGPStatusResponse{})
}

func (s *fakeGateway) ListBGPPeers(_ context.Context, req *platformv1.ListBGPPeersRequest) (*platformv1.ListBGPPeersResponse, error) {
	return reply(s.rec, "ListBGPPeers", req, &platformv1.ListBGPPeersResponse{})
}

func (s *fakeGateway) AnnouncePrefix(_ context.Context, req *platformv1.AnnouncePrefixRequest) (*platformv1.AnnouncePrefixResponse, error) {
	return reply(s.rec, "AnnouncePrefix", req, &platformv1.AnnouncePrefixResponse{})
}

func (s *fakeGateway) WithdrawPrefix(_ context.Context, req *platformv1.WithdrawPrefixRequest) (*platformv1.WithdrawPrefixResponse, error) {
	return reply(s.rec, "WithdrawPrefix", req, &platformv1.WithdrawPrefixResponse{})
}

func (s *fakeGateway) ListAnnouncedPrefixes(_ context.Context, req *platformv1.ListAnnouncedPrefixesRequest) (*platformv1.ListAnnouncedPrefixesResponse, error) {
	return reply(s.rec, "ListAnnouncedPrefixes", req, &platformv1.ListAnnouncedPrefixesResponse{})
}

func (s *fakeGateway) CreateIPAMPool(_ context.Context, req *platformv1.CreateIPAMPoolRequest) (*platformv1.CreateIPAMPoolResponse, error) {
	return reply(s.rec, "CreateIPAMPool", req, &platformv1.CreateIPAMPoolResponse{})
}

func (s *fakeGateway) GetIPAMPool(_ context.Context, req *platformv1.GetIPAMPoolRequest) (*platformv1.GetIPAMPoolResponse, error) {
	return reply(s.rec, "GetIPAMPool", req, &platformv1.GetIPAMPoolResponse{})
}

func (s *fakeGateway) UpdateIPAMPool(_ context.Context, req *platformv1.UpdateIPAMPoolRequest) (*platformv1.UpdateIPAMPoolResponse, error) {
	return reply(s.rec, "UpdateIPAMPool", req, &platformv1.UpdateIPAMPoolResponse{})
}

func (s *fakeGateway) DeleteIPAMPool(_ context.Context, req *platformv1.DeleteIPAMPoolRequest) (*platformv1.DeleteIPAMPoolResponse, error) {
	return reply(s.rec, "DeleteIPAMPool", req, &platformv1.DeleteIPAMPoolResponse{})
}

func (s *fakeGateway) ListIPAMPools(_ context.Context, req *platformv1.ListIPAMPoolsRequest) (*platformv1.ListIPAMPoolsResponse, error) {
	return reply(s.rec, "ListIPAMPools", req, &platformv1.ListIPAMPoolsResponse{})
}

func (s *fakeGateway) AllocateIP(_ context.Context, req *platformv1.AllocateIPRequest) (*platformv1.AllocateIPResponse, error) {
	return reply(s.rec, "AllocateIP", req, &platformv1.AllocateIPResponse{})
}

func (s *fakeGateway) ReleaseIP(_ context.Context, req *platformv1.ReleaseIPRequest) (*platformv1.ReleaseIPResponse, error) {
	return reply(s.rec, "ReleaseIP", req, &platformv1.ReleaseIPResponse{})
}

func (s *fakeGateway) ListAllocations(_ context.Context, req *platformv1.ListAllocationsRequest) (*platformv1.ListAllocationsResponse, error) {
	return reply(s.rec, "ListAllocations", req, &platformv1.ListAllocationsResponse{})
}

func (s *fakeGateway) AddVIP(_ context.Context, req *platformv1.AddVIPRequest) (*platformv1.AddVIPResponse, error) {
	return reply(s.rec, "AddVIP", req, &platformv1.AddVIPResponse{})
}

func (s *fakeGateway) RemoveVIP(_ context.Context, req *platformv1.RemoveVIPRequest) (*platformv1.RemoveVIPResponse, error) {
	return reply(s.rec, "RemoveVIP", req, &platformv1.RemoveVIPResponse{})
}

func (s *fakeGateway) GetVIP(_ context.Context, req *platformv1.GetVIPRequest) (*platformv1.GetVIPResponse, error) {
	return reply(s.rec, "GetVIP", req, &platformv1.GetVIPResponse{})
}

func (s *fakeGateway) ListVIPs(_ context.Context, req *platformv1.ListVIPsRequest) (*platformv1.ListVIPsResponse, error) {
	return reply(s.rec, "ListVIPs", req, &platformv1.ListVIPsResponse{})
}

func (s *fakeGateway) SetVIPBackends(_ context.Context, req *platformv1.SetVIPBackendsRequest) (*platformv1.SetVIPBackendsResponse, error) {
	return reply(s.rec, "SetVIPBackends", req, &platformv1.SetVIPBackendsResponse{})
}

func (s *fakeGateway) GetLBStatus(_ context.Context, req *platformv1.GetLBStatusRequest) (*platformv1.GetLBStatusResponse, error) {
	return reply(s.rec, "GetLBStatus", req, &platformv1.GetLBStatusResponse{})
}

func (s *fakeGateway) GetNAT64Status(_ context.Context, req *platformv1.GetNAT64StatusRequest) (*platformv1.GetNAT64StatusResponse, error) {
	return reply(s.rec, "GetNAT64Status", req, &platformv1.GetNAT64StatusResponse{})
}

func (s *fakeGateway) GetPerfFlows(_ context.Context, req *platformv1.GetPerfFlowsRequest) (*platformv1.GetPerfFlowsResponse, error) {
	return reply(s.rec, "GetPerfFlows", req, &platformv1.GetPerfFlowsResponse{})
}

func (s *fakeGateway) GetPerfDatapath(_ context.Context, req *platformv1.GetPerfDatapathRequest) (*platformv1.GetPerfDatapathResponse, error) {
	return reply(s.rec, "GetPerfDatapath", req, &platformv1.GetPerfDatapathResponse{})
}

func (s *fakeGateway) GetPerfConntrack(_ context.Context, req *platformv1.GetPerfConntrackRequest) (*platformv1.GetPerfConntrackResponse, error) {
	return reply(s.rec, "GetPerfConntrack", req, &platformv1.GetPerfConntrackResponse{})
}

type fakeOverlay struct {
	platformv1.UnimplementedOverlayServiceServer
	rec *recorder
}

func (s *fakeOverlay) GetOverlayStatus(_ context.Context, req *platformv1.GetOverlayStatusRequest) (*platformv1.GetOverlayStatusResponse, error) {
	return reply(s.rec, "GetOverlayStatus", req, &platformv1.GetOverlayStatusResponse{})
}

func (s *fakeOverlay) ListVTEPs(_ context.Context, req *platformv1.ListVTEPsRequest) (*platformv1.ListVTEPsResponse, error) {
	return reply(s.rec, "ListVTEPs", req, &platformv1.ListVTEPsResponse{})
}

func (s *fakeOverlay) GetVTEP(_ context.Context, req *platformv1.GetVTEPRequest) (*platformv1.GetVTEPResponse, error) {
	return reply(s.rec, "GetVTEP", req, &platformv1.GetVTEPResponse{})
}

func (s *fakeOverlay) CreateVNI(_ context.Context, req *platformv1.CreateVNIRequest) (*platformv1.CreateVNIResponse, error) {
	return reply(s.rec, "CreateVNI", req, &platformv1.CreateVNIResponse{})
}

func (s *fakeOverlay) DeleteVNI(_ context.Context, req *platformv1.DeleteVNIRequest) (*platformv1.DeleteVNIResponse, error) {
	return reply(s.rec, "DeleteVNI", req, &platformv1.DeleteVNIResponse{})
}

func (s *fakeOverlay) ListVNIs(_ context.Context, req *platformv1.ListVNIsRequest) (*platformv1.ListVNIsResponse, error) {
	return reply(s.rec, "ListVNIs", req, &platformv1.ListVNIsResponse{})
}

func (s *fakeOverlay) ListTunnels(_ context.Context, req *platformv1.ListTunnelsRequest) (*platformv1.ListTunnelsResponse, error) {
	return reply(s.rec, "ListTunnels", req, &platformv1.ListTunnelsResponse{})
}

func (s *fakeOverlay) ListRemoteMACs(_ context.Context, req *platformv1.ListRemoteMACsRequest) (*platformv1.ListRemoteMACsResponse, error) {
	return reply(s.rec, "ListRemoteMACs", req, &platformv1.ListRemoteMACsResponse{})
}

func (s *fakeOverlay) ForgetMAC(_ context.Context, req *platformv1.ForgetMACRequest) (*platformv1.ForgetMACResponse, error) {
	return reply(s.rec, "ForgetMAC", req, &platformv1.ForgetMACResponse{})
}
