package sdn

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func (s *scriptedSDNServer) DeletePolicy(_ context.Context, req *platformv1.DeletePolicyRequest) (*platformv1.DeletePolicyResponse, error) {
	return answer[*platformv1.DeletePolicyResponse](s, req)
}

// TestFlowAndPolicyRoutes: the routes the web SDK calls for FlushFlows,
// GetFlowStats and DeletePolicy (#2064) reach the service with the path's
// bridge, flow and policy, and answer the service's reply.
func TestFlowAndPolicyRoutes(t *testing.T) {
	ok := &platformv1.Status{Success: true}
	tests := []struct {
		name, method, target, body string
		want, resp, reply          proto.Message
	}{
		{
			name: "FlushFlows", method: http.MethodPost, target: "/api/v1/sdn/bridges/br0/flows/flush",
			body:  `{"bridgeId":"ignored","table":"FLOW_TABLE_1"}`,
			want:  &platformv1.FlushFlowsRequest{BridgeId: "br0", Table: platformv1.FlowTable_FLOW_TABLE_1},
			resp:  &platformv1.FlushFlowsResponse{Status: ok, DeletedCount: 3},
			reply: &platformv1.FlushFlowsResponse{},
		},
		{
			name: "FlushFlowsWithoutABody", method: http.MethodPost, target: "/api/v1/sdn/bridges/br0/flows/flush",
			want:  &platformv1.FlushFlowsRequest{BridgeId: "br0"},
			resp:  &platformv1.FlushFlowsResponse{Status: ok},
			reply: &platformv1.FlushFlowsResponse{},
		},
		{
			name: "GetFlowStats", method: http.MethodGet, target: "/api/v1/sdn/bridges/br0/flows/0x1/stats",
			want:  &platformv1.GetFlowStatsRequest{BridgeId: "br0", FlowId: "0x1"},
			resp:  &platformv1.GetFlowStatsResponse{Stats: &platformv1.FlowStats{PacketCount: 12, ByteCount: 960}},
			reply: &platformv1.GetFlowStatsResponse{},
		},
		{
			name: "DeletePolicy", method: http.MethodDelete, target: "/api/v1/sdn/policies/p1",
			want:  &platformv1.DeletePolicyRequest{PolicyId: "p1"},
			resp:  &platformv1.DeletePolicyResponse{Status: ok},
			reply: &platformv1.DeletePolicyResponse{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := &scriptedSDNServer{resp: tc.resp}
			rec := serve(server, tc.method, tc.target, tc.body)

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.True(t, proto.Equal(tc.want, server.got), "request = %v, want %v", server.got, tc.want)
			payload(t, rec, tc.reply)
			assert.True(t, proto.Equal(tc.resp, tc.reply), "reply = %v, want %v", tc.reply, tc.resp)
		})
	}
}

// TestFlowAndPolicyRoutesErrors: the new routes answer 503 without a
// service and the service's status otherwise.
func TestFlowAndPolicyRoutesErrors(t *testing.T) {
	routes := []struct{ method, target string }{
		{http.MethodPost, "/api/v1/sdn/bridges/br0/flows/flush"},
		{http.MethodGet, "/api/v1/sdn/bridges/br0/flows/0x1/stats"},
		{http.MethodDelete, "/api/v1/sdn/policies/p1"},
	}
	for _, route := range routes {
		t.Run(route.method+" "+route.target, func(t *testing.T) {
			rec := serve(nil, route.method, route.target, "")
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())

			server := &scriptedSDNServer{err: status.Error(codes.NotFound, "not found")}
			rec = serve(server, route.method, route.target, "")
			assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
			assert.NotNil(t, server.got, "the route did not reach the service")
		})
	}
}
