// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

package daemon

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestRESTServer_ClusterRoutesMounted_NoBackend verifies that
// SetClusterService(nil) still mounts the routes so the dashboard sees
// 503 (not 404). 503 lets the WebUI render an actionable empty state.
func TestRESTServer_ClusterRoutesMounted_NoBackend(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	mustMountS6(t, s.SetClusterService(nil, s6RESTGuard()))

	code, body := doJSONAs(t, s, s6OperatorToken, http.MethodGet, "/api/v1/cluster/status", nil)
	if code != http.StatusServiceUnavailable {
		t.Errorf("GET /cluster/status: want 503, got %d (body=%s)", code, body)
	}
	var resp map[string]string
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	if resp["error"] == "" {
		t.Errorf("expected error message, got %v", resp)
	}
}

// clusterRESTCases are valid requests for the five cluster routes.
var clusterRESTCases = []struct {
	method string
	path   string
	body   interface{}
}{
	{http.MethodGet, "/api/v1/cluster/status", nil},
	{http.MethodGet, "/api/v1/cluster/nodes", nil},
	{http.MethodPost, "/api/v1/cluster/bootstrap", map[string]string{"cluster_name": "alpha", "node_name": "node-1"}},
	{http.MethodPost, "/api/v1/cluster/join", map[string]interface{}{"node_name": "node-1", "seed_addresses": []string{"10.0.0.2:7001"}}},
	{http.MethodPost, "/api/v1/cluster/leave", map[string]string{}},
}

// newClusterRESTServer mounts the cluster routes over the gRPC service the
// daemon registers, backed by svc (nil leaves the backend unset).
func newClusterRESTServer(t *testing.T, svc ClusterServicer) *RESTServer {
	t.Helper()
	s := newTestRESTServerForPhase35(t)
	service, backend := registerClusterGRPCService(logging.DefaultLogger())
	backend.set(svc)
	mustMountS6(t, s.SetClusterService(service, s6RESTGuard()))
	return s
}

// TestRESTServer_ClusterRoutes_ServicerUnset verifies every route reports
// 503 while the registered service has no cluster servicer behind it.
func TestRESTServer_ClusterRoutes_ServicerUnset(t *testing.T) {
	s := newClusterRESTServer(t, nil)
	for _, tt := range clusterRESTCases {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			code, body := doJSONAs(t, s, s6OperatorToken, tt.method, tt.path, tt.body)
			if code != http.StatusServiceUnavailable {
				t.Errorf("want 503, got %d (body=%s)", code, body)
			}
		})
	}
}

// TestRESTServer_ClusterRoutes_ServicerResults verifies every route
// returns 200 with the cluster servicer's result.
func TestRESTServer_ClusterRoutes_ServicerResults(t *testing.T) {
	fake := &fakeClusterServicer{statusInfo: stockStatus(), nodes: stockNodes(), nodeID: 1, leader: true}
	s := newClusterRESTServer(t, fake)
	for _, tt := range clusterRESTCases {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			code, body := doJSONAs(t, s, s6OperatorToken, tt.method, tt.path, tt.body)
			if code != http.StatusOK {
				t.Fatalf("want 200, got %d (body=%s)", code, body)
			}
		})
	}
	if fake.bootstrapCalled != 1 || fake.joinCalled != 1 || fake.leaveCalled != 1 {
		t.Errorf("calls bootstrap=%d join=%d leave=%d, want 1 each",
			fake.bootstrapCalled, fake.joinCalled, fake.leaveCalled)
	}

	code, body := doJSONAs(t, s, s6OperatorToken, http.MethodGet, "/api/v1/cluster/nodes", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /cluster/nodes: want 200, got %d", code)
	}
	var resp struct {
		Nodes []struct {
			ID string `json:"id"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	if len(resp.Nodes) != 2 || resp.Nodes[0].ID != "1" || resp.Nodes[1].ID != "2" {
		t.Errorf("nodes = %+v, want ids 1 and 2", resp.Nodes)
	}
}

// TestRESTServer_ClusterRoutes_Errors verifies request and servicer
// errors reach REST with their mapped HTTP status.
func TestRESTServer_ClusterRoutes_Errors(t *testing.T) {
	fake := &fakeClusterServicer{nodeID: 1, statusErr: errors.New("raft down")}
	s := newClusterRESTServer(t, fake)

	tests := []struct {
		name   string
		method string
		path   string
		body   interface{}
		want   int
	}{
		{"bootstrap without names", http.MethodPost, "/api/v1/cluster/bootstrap", map[string]string{}, http.StatusBadRequest},
		{"leave of another node", http.MethodPost, "/api/v1/cluster/leave", map[string]string{"node_id": "2"}, http.StatusBadRequest},
		{"status failure", http.MethodGet, "/api/v1/cluster/status", nil, http.StatusInternalServerError},
		{"malformed body", http.MethodPost, "/api/v1/cluster/join", "not an object", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body := doJSONAs(t, s, s6OperatorToken, tt.method, tt.path, tt.body)
			if code != tt.want {
				t.Errorf("want %d, got %d (body=%s)", tt.want, code, body)
			}
		})
	}
	if fake.leaveCalled != 0 {
		t.Errorf("Leave called %d times for another node, want 0", fake.leaveCalled)
	}
}

// TestRESTServer_ClusterRoutes_FailedPreconditionIsConflict checks the
// cluster routes answer a FailedPrecondition (here, a cluster that is not
// initialised) with 409 Conflict, as every other REST writer does (#665),
// not as an internal error.
func TestRESTServer_ClusterRoutes_FailedPreconditionIsConflict(t *testing.T) {
	fake := &fakeClusterServicer{nodeID: 1, statusErr: grpcapi.ErrClusterNotInitialized{}}
	s := newClusterRESTServer(t, fake)

	code, body := doJSONAs(t, s, s6OperatorToken, http.MethodGet, "/api/v1/cluster/status", nil)
	if code != http.StatusConflict {
		t.Errorf("want %d, got %d (body=%s)", http.StatusConflict, code, body)
	}
}
