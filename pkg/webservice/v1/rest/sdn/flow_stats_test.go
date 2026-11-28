package sdn

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func (s *scriptedSDNServer) FlushFlows(_ context.Context, req *platformv1.FlushFlowsRequest) (*platformv1.FlushFlowsResponse, error) {
	return answer[*platformv1.FlushFlowsResponse](s, req)
}

func (s *scriptedSDNServer) GetFlowStats(_ context.Context, req *platformv1.GetFlowStatsRequest) (*platformv1.GetFlowStatsResponse, error) {
	return answer[*platformv1.GetFlowStatsResponse](s, req)
}

// The JS SDK's flushFlows sends POST /bridges/{bridgeId}/flows/flush with
// body {table}; the bridge comes from the path.
func TestFlushFlows_FlushesTheBridgeTable(t *testing.T) {
	want := &platformv1.FlushFlowsResponse{DeletedCount: 3}
	server := &scriptedSDNServer{resp: want}

	rec := serve(server, http.MethodPost, "/api/v1/sdn/bridges/br0/flows/flush", `{"table":"FLOW_TABLE_1"}`)

	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, proto.Equal(&platformv1.FlushFlowsRequest{
		BridgeId: "br0",
		Table:    platformv1.FlowTable_FLOW_TABLE_1,
	}, server.got), "got %v", server.got)
	got := &platformv1.FlushFlowsResponse{}
	payload(t, rec, got)
	assert.True(t, proto.Equal(want, got), "got %v", got)

	empty := &scriptedSDNServer{resp: want}
	rec = serve(empty, http.MethodPost, "/api/v1/sdn/bridges/br0/flows/flush", "")

	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, proto.Equal(&platformv1.FlushFlowsRequest{
		BridgeId: "br0",
		Table:    platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED,
	}, empty.got), "got %v", empty.got)
}

// The JS SDK's getFlowStats sends GET /bridges/{bridgeId}/flows/{flowId}/stats.
func TestGetFlowStats_ReadsTheFlowsCounters(t *testing.T) {
	want := &platformv1.GetFlowStatsResponse{Stats: &platformv1.FlowStats{PacketCount: 12, ByteCount: 3400}}
	server := &scriptedSDNServer{resp: want}

	rec := serve(server, http.MethodGet, "/api/v1/sdn/bridges/br0/flows/f1/stats", "")

	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, proto.Equal(&platformv1.GetFlowStatsRequest{BridgeId: "br0", FlowId: "f1"}, server.got), "got %v", server.got)
	got := &platformv1.GetFlowStatsResponse{}
	payload(t, rec, got)
	assert.True(t, proto.Equal(want, got), "got %v", got)
}

var flowStatsRoutes = []struct{ method, target, body string }{
	{http.MethodPost, "/api/v1/sdn/bridges/br0/flows/flush", `{"table":"FLOW_TABLE_1"}`},
	{http.MethodGet, "/api/v1/sdn/bridges/br0/flows/f1/stats", ""},
}

func TestFlowStatsRoutes_NoServerIsServiceUnavailable(t *testing.T) {
	for _, route := range flowStatsRoutes {
		rec := serve(nil, route.method, route.target, route.body)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "%s %s: %s", route.method, route.target, rec.Body.String())
	}
}

func TestFlowStatsRoutes_WriteTheServiceError(t *testing.T) {
	for _, route := range flowStatsRoutes {
		server := &scriptedSDNServer{err: status.Error(codes.NotFound, "bridge not found")}
		rec := serve(server, route.method, route.target, route.body)
		assert.NotNil(t, server.got, "%s %s did not reach the SDN service", route.method, route.target)
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s %s: %s", route.method, route.target, rec.Body.String())
	}
}
