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
	"encoding/json"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestOrchestratorRoutesMatchTheDaemonHandlers pins every OrchestratorService
// method to the route pkg/api/rest/orchestrator_handlers.go mounts.
func TestOrchestratorRoutesMatchTheDaemonHandlers(t *testing.T) {
	cases := []struct {
		method string
		args   proto.Message
		verb   string
		path   string
	}{
		{platformv1.OrchestratorService_Health_FullMethodName, &platformv1.OrchestratorHealthRequest{},
			http.MethodGet, "/api/v1/orchestrator/health"},
		{platformv1.OrchestratorService_ListAgents_FullMethodName, &platformv1.ListOrchestratorAgentsRequest{TenantId: "acme"},
			http.MethodGet, "/api/v1/orchestrator/tenants/acme/agents"},
		{platformv1.OrchestratorService_GetAgent_FullMethodName, &platformv1.GetOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"},
			http.MethodGet, "/api/v1/orchestrator/tenants/acme/agents/a1"},
		{platformv1.OrchestratorService_DisableAgent_FullMethodName, &platformv1.DisableOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"},
			http.MethodPost, "/api/v1/orchestrator/tenants/acme/agents/a1/disable"},
		{platformv1.OrchestratorService_EnableAgent_FullMethodName, &platformv1.EnableOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"},
			http.MethodPost, "/api/v1/orchestrator/tenants/acme/agents/a1/enable"},
		{platformv1.OrchestratorService_ListSessions_FullMethodName, &platformv1.ListOrchestratorSessionsRequest{},
			http.MethodGet, "/api/v1/orchestrator/sessions"},
		{platformv1.OrchestratorService_CloseSession_FullMethodName, &platformv1.CloseOrchestratorSessionRequest{SessionId: "s1"},
			http.MethodDelete, "/api/v1/orchestrator/sessions/s1"},
		{platformv1.OrchestratorService_ListJobs_FullMethodName, &platformv1.ListOrchestratorJobsRequest{TenantId: "acme"},
			http.MethodGet, "/api/v1/orchestrator/tenants/acme/jobs"},
		{platformv1.OrchestratorService_GetJob_FullMethodName, &platformv1.GetOrchestratorJobRequest{TenantId: "acme", JobId: "j1"},
			http.MethodGet, "/api/v1/orchestrator/tenants/acme/jobs/j1"},
		{platformv1.OrchestratorService_CancelJob_FullMethodName, &platformv1.CancelOrchestratorJobRequest{TenantId: "acme", JobId: "j1"},
			http.MethodPost, "/api/v1/orchestrator/tenants/acme/jobs/j1/cancel"},
	}
	if len(platformv1.OrchestratorService_ServiceDesc.Methods) != len(cases) {
		t.Fatalf("OrchestratorService has %d methods, the test pins %d", len(platformv1.OrchestratorService_ServiceDesc.Methods), len(cases))
	}

	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			verb, path, _, err := route(tc.method, tc.args)
			if err != nil {
				t.Fatalf("route() error = %v", err)
			}
			if verb != tc.verb || path != tc.path {
				t.Fatalf("route() = %s %s, want %s %s", verb, path, tc.verb, tc.path)
			}
		})
	}
}

// TestOrchestratorListFiltersTravelInTheBody proves the daemon can decode the
// filters and paging a list request carries beside its path variables.
func TestOrchestratorListFiltersTravelInTheBody(t *testing.T) {
	args := &platformv1.ListOrchestratorJobsRequest{
		TenantId: "acme",
		Statuses: []string{"running", "queued"},
		Page:     &platformv1.OrchestratorPage{Limit: 20, Offset: 40},
	}
	_, _, body, err := route(platformv1.OrchestratorService_ListJobs_FullMethodName, args)
	if err != nil {
		t.Fatalf("route() error = %v", err)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	got := &platformv1.ListOrchestratorJobsRequest{}
	if err := protojson.Unmarshal(encoded, got); err != nil {
		t.Fatalf("the daemon cannot decode body %s: %v", encoded, err)
	}
	if !proto.Equal(got.GetPage(), args.GetPage()) || len(got.GetStatuses()) != 2 {
		t.Fatalf("body = %v, want statuses and page of %v", got, args)
	}
}

// TestOrchestratorRoutesRefuseIncompleteRequests checks a missing path
// variable fails before any request leaves the client.
func TestOrchestratorRoutesRefuseIncompleteRequests(t *testing.T) {
	cases := map[string]proto.Message{
		platformv1.OrchestratorService_GetAgent_FullMethodName:     &platformv1.GetOrchestratorAgentRequest{TenantId: "acme"},
		platformv1.OrchestratorService_CloseSession_FullMethodName: &platformv1.CloseOrchestratorSessionRequest{},
		platformv1.OrchestratorService_CancelJob_FullMethodName:    &platformv1.CancelOrchestratorJobRequest{JobId: "j1"},
	}
	for method, args := range cases {
		if _, _, _, err := route(method, args); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: route() error = %v, want InvalidArgument", method, err)
		}
	}
}
