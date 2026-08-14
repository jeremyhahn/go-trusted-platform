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

package gateway

import (
	"context"
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
)

// errFakeTransport is the sentinel failure injected by the fake client.
var errFakeTransport = errors.New("transport failure")

// fakePerfGatewayClient overrides the perf RPCs; the embedded interface
// leaves every other method unimplemented (calls would panic, which is
// acceptable in these focused unit tests).
type fakePerfGatewayClient struct {
	platformv1.GatewayServiceClient

	flowsResp     *platformv1.GetPerfFlowsResponse
	datapathResp  *platformv1.GetPerfDatapathResponse
	conntrackResp *platformv1.GetPerfConntrackResponse
	err           error

	lastFlowsReq     *platformv1.GetPerfFlowsRequest
	lastDatapathReq  *platformv1.GetPerfDatapathRequest
	lastConntrackReq *platformv1.GetPerfConntrackRequest
}

func (f *fakePerfGatewayClient) GetPerfFlows(ctx context.Context, in *platformv1.GetPerfFlowsRequest, opts ...grpc.CallOption) (*platformv1.GetPerfFlowsResponse, error) {
	f.lastFlowsReq = in
	if f.err != nil {
		return nil, f.err
	}
	return f.flowsResp, nil
}

func (f *fakePerfGatewayClient) GetPerfDatapath(ctx context.Context, in *platformv1.GetPerfDatapathRequest, opts ...grpc.CallOption) (*platformv1.GetPerfDatapathResponse, error) {
	f.lastDatapathReq = in
	if f.err != nil {
		return nil, f.err
	}
	return f.datapathResp, nil
}

func (f *fakePerfGatewayClient) GetPerfConntrack(ctx context.Context, in *platformv1.GetPerfConntrackRequest, opts ...grpc.CallOption) (*platformv1.GetPerfConntrackResponse, error) {
	f.lastConntrackReq = in
	if f.err != nil {
		return nil, f.err
	}
	return f.conntrackResp, nil
}

func TestGetPerfFlows(t *testing.T) {
	fake := &fakePerfGatewayClient{flowsResp: &platformv1.GetPerfFlowsResponse{
		Installed:      500,
		DurationNs:     1_000_000,
		FlowsPerSecond: 500000,
		Batched:        true,
		Bridge:         "br-int",
	}}
	client := NewClientFromGRPC(fake)

	resp, err := client.GetPerfFlows(context.Background(), 500, true, "br-int")
	if err != nil {
		t.Fatalf("GetPerfFlows: %v", err)
	}
	if resp.GetInstalled() != 500 || !resp.GetBatched() {
		t.Errorf("resp = %+v", resp)
	}
	if fake.lastFlowsReq.GetCount() != 500 || !fake.lastFlowsReq.GetBatch() || fake.lastFlowsReq.GetBridge() != "br-int" {
		t.Errorf("request = %+v", fake.lastFlowsReq)
	}
}

func TestGetPerfFlowsError(t *testing.T) {
	client := NewClientFromGRPC(&fakePerfGatewayClient{err: errFakeTransport})

	_, err := client.GetPerfFlows(context.Background(), 10, false, "")
	var perfErr *ErrPerfFlowsFailed
	if !errors.As(err, &perfErr) {
		t.Fatalf("err = %v, want ErrPerfFlowsFailed", err)
	}
	if !errors.Is(err, errFakeTransport) {
		t.Errorf("cause not preserved: %v", err)
	}
}

func TestGetPerfDatapath(t *testing.T) {
	fake := &fakePerfGatewayClient{datapathResp: &platformv1.GetPerfDatapathResponse{
		Hits:             5000,
		Misses:           20,
		Lost:             1,
		HwOffloadEnabled: true,
		DatapathType:     "system",
	}}
	client := NewClientFromGRPC(fake)

	resp, err := client.GetPerfDatapath(context.Background(), "br-int")
	if err != nil {
		t.Fatalf("GetPerfDatapath: %v", err)
	}
	if resp.GetHits() != 5000 || !resp.GetHwOffloadEnabled() {
		t.Errorf("resp = %+v", resp)
	}
	if fake.lastDatapathReq.GetBridge() != "br-int" {
		t.Errorf("request bridge = %q", fake.lastDatapathReq.GetBridge())
	}
}

func TestGetPerfDatapathError(t *testing.T) {
	client := NewClientFromGRPC(&fakePerfGatewayClient{err: errFakeTransport})

	_, err := client.GetPerfDatapath(context.Background(), "")
	var perfErr *ErrPerfDatapathFailed
	if !errors.As(err, &perfErr) {
		t.Fatalf("err = %v, want ErrPerfDatapathFailed", err)
	}
}

func TestGetPerfConntrack(t *testing.T) {
	fake := &fakePerfGatewayClient{conntrackResp: &platformv1.GetPerfConntrackResponse{
		TotalEntries: 4,
		PerZone:      map[uint32]uint64{12: 2},
	}}
	client := NewClientFromGRPC(fake)

	zone := uint32(12)
	resp, err := client.GetPerfConntrack(context.Background(), &zone)
	if err != nil {
		t.Fatalf("GetPerfConntrack: %v", err)
	}
	if resp.GetTotalEntries() != 4 || resp.GetPerZone()[12] != 2 {
		t.Errorf("resp = %+v", resp)
	}
	if fake.lastConntrackReq.Zone == nil || *fake.lastConntrackReq.Zone != 12 {
		t.Errorf("request zone = %v", fake.lastConntrackReq.Zone)
	}
}

func TestGetPerfConntrackAllZones(t *testing.T) {
	fake := &fakePerfGatewayClient{conntrackResp: &platformv1.GetPerfConntrackResponse{}}
	client := NewClientFromGRPC(fake)

	if _, err := client.GetPerfConntrack(context.Background(), nil); err != nil {
		t.Fatalf("GetPerfConntrack: %v", err)
	}
	if fake.lastConntrackReq.Zone != nil {
		t.Errorf("request zone = %v, want nil", fake.lastConntrackReq.Zone)
	}
}

func TestGetPerfConntrackError(t *testing.T) {
	client := NewClientFromGRPC(&fakePerfGatewayClient{err: errFakeTransport})

	_, err := client.GetPerfConntrack(context.Background(), nil)
	var perfErr *ErrPerfConntrackFailed
	if !errors.As(err, &perfErr) {
		t.Fatalf("err = %v, want ErrPerfConntrackFailed", err)
	}
}
