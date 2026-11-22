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

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// bodyCountingClusterServer counts the Bootstrap, Join and Leave calls that
// reach the cluster server.
type bodyCountingClusterServer struct {
	platformv1.UnimplementedClusterServiceServer
	bootstraps, joins, leaves int
}

func (s *bodyCountingClusterServer) Bootstrap(context.Context, *platformv1.BootstrapClusterRequest) (*platformv1.BootstrapClusterResponse, error) {
	s.bootstraps++
	return &platformv1.BootstrapClusterResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (s *bodyCountingClusterServer) Join(context.Context, *platformv1.JoinClusterRequest) (*platformv1.JoinClusterResponse, error) {
	s.joins++
	return &platformv1.JoinClusterResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (s *bodyCountingClusterServer) Leave(context.Context, *platformv1.LeaveClusterRequest) (*platformv1.LeaveClusterResponse, error) {
	s.leaves++
	return &platformv1.LeaveClusterResponse{Status: &platformv1.Status{Success: true}}, nil
}

func TestClusterHandlers_OversizedBodyIs413(t *testing.T) {
	big := strings.Repeat("a", 2<<20)
	routes := []struct {
		name  string
		field string
		call  func(h *ClusterHandlers) http.HandlerFunc
		calls func(s *bodyCountingClusterServer) int
	}{
		{"bootstrap", "cluster_name", func(h *ClusterHandlers) http.HandlerFunc { return h.bootstrap }, func(s *bodyCountingClusterServer) int { return s.bootstraps }},
		{"join", "node_name", func(h *ClusterHandlers) http.HandlerFunc { return h.join }, func(s *bodyCountingClusterServer) int { return s.joins }},
		{"leave", "node_id", func(h *ClusterHandlers) http.HandlerFunc { return h.leave }, func(s *bodyCountingClusterServer) int { return s.leaves }},
	}
	cases := []struct {
		name      string
		body      func(field string) string
		wantCode  int
		wantCalls int
	}{
		{"oversized", func(f string) string { return `{"` + f + `":"` + big + `"}` }, http.StatusRequestEntityTooLarge, 0},
		{"small valid", func(f string) string { return `{"` + f + `":"lab"}` }, http.StatusOK, 1},
		{"small malformed", func(f string) string { return `{"` + f + `":` }, http.StatusBadRequest, 0},
	}
	for _, rt := range routes {
		for _, tc := range cases {
			t.Run(rt.name+"/"+tc.name, func(t *testing.T) {
				srv := &bodyCountingClusterServer{}
				h := NewClusterHandlers(srv, nil)
				req := httptest.NewRequest(http.MethodPost, "/cluster/"+rt.name, strings.NewReader(tc.body(rt.field)))
				rec := httptest.NewRecorder()
				rt.call(h)(rec, req)
				if rec.Code != tc.wantCode {
					t.Fatalf("status = %d, want %d", rec.Code, tc.wantCode)
				}
				if got := rt.calls(srv); got != tc.wantCalls {
					t.Fatalf("server calls = %d, want %d", got, tc.wantCalls)
				}
				if tc.wantCode != http.StatusOK {
					var body map[string]string
					if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
						t.Fatalf("error body is not JSON: %v", err)
					}
					if body["error"] == "" {
						t.Fatalf("error body has no error: %q", rec.Body.String())
					}
				}
			})
		}
	}
}
