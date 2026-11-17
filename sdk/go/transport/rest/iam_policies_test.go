package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// iamPolicyCall is one IAM policy RPC with the request it sends, the reply
// it decodes into, and the HTTP route the webservice serves it on
// (pkg/webservice/v1/rest/iam/router.go registerPolicyRoutes).
type iamPolicyCall struct {
	name       string
	grpcMethod string
	req        proto.Message
	resp       proto.Message
	wantMethod string
	wantPath   string
}

func iamPolicyCalls() []iamPolicyCall {
	spec := []byte("rules:\n  - effect: allow\n")
	return []iamPolicyCall{
		{
			name:       "CreatePolicy",
			grpcMethod: platformv1.PlatformIAMService_CreatePolicy_FullMethodName,
			req:        &platformv1.CreateIAMPolicyRequest{TenantId: "t1", Name: "p1", SpecYaml: spec},
			resp:       &platformv1.IAMPolicyResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/iam/tenants/t1/policies",
		},
		{
			name:       "ListPolicies",
			grpcMethod: platformv1.PlatformIAMService_ListPolicies_FullMethodName,
			req:        &platformv1.ListIAMPoliciesRequest{TenantId: "t1"},
			resp:       &platformv1.ListIAMPoliciesResponse{},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/iam/tenants/t1/policies",
		},
		{
			name:       "GetPolicy",
			grpcMethod: platformv1.PlatformIAMService_GetPolicy_FullMethodName,
			req:        &platformv1.GetIAMPolicyRequest{TenantId: "t1", PolicyName: "p1"},
			resp:       &platformv1.IAMPolicyResponse{},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/iam/tenants/t1/policies/p1",
		},
		{
			name:       "UpdatePolicy",
			grpcMethod: platformv1.PlatformIAMService_UpdatePolicy_FullMethodName,
			req:        &platformv1.UpdateIAMPolicyRequest{TenantId: "t1", PolicyName: "p1", SpecYaml: spec},
			resp:       &platformv1.IAMPolicyResponse{},
			wantMethod: http.MethodPut,
			wantPath:   "/api/v1/iam/tenants/t1/policies/p1",
		},
		{
			name:       "DeletePolicy",
			grpcMethod: platformv1.PlatformIAMService_DeletePolicy_FullMethodName,
			req:        &platformv1.DeleteIAMPolicyRequest{TenantId: "t1", PolicyName: "p1"},
			resp:       &platformv1.DeleteIAMPolicyResponse{},
			wantMethod: http.MethodDelete,
			wantPath:   "/api/v1/iam/tenants/t1/policies/p1",
		},
		{
			name:       "ValidatePolicy",
			grpcMethod: platformv1.PlatformIAMService_ValidatePolicy_FullMethodName,
			req:        &platformv1.ValidateIAMPolicyRequest{TenantId: "t1", SpecYaml: spec},
			resp:       &platformv1.ValidateIAMPolicyResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/iam/tenants/t1/policies/validate",
		},
		{
			name:       "TestPolicy",
			grpcMethod: platformv1.PlatformIAMService_TestPolicy_FullMethodName,
			req: &platformv1.TestIAMPolicyRequest{
				TenantId: "t1", SubjectId: "u1", Action: "read", Resource: "documents/7",
			},
			resp:       &platformv1.TestIAMPolicyResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/iam/tenants/t1/policies/test",
		},
	}
}

// TestIAMPolicyRoutes_ResolveToTheServedTenantRoutes pins each policy RPC to
// the tenant-scoped route the webservice serves. With no route the adapter
// derived POST /api/v1/platformiam/<method>, which no server serves (#1958).
func TestIAMPolicyRoutes_ResolveToTheServedTenantRoutes(t *testing.T) {
	for _, tc := range iamPolicyCalls() {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod, gotPath string
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health/live" {
					w.WriteHeader(http.StatusOK)
					return
				}
				gotMethod, gotPath = r.Method, r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			})

			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if gotMethod != tc.wantMethod || gotPath != tc.wantPath {
				t.Errorf("request = %s %s, want %s %s", gotMethod, gotPath, tc.wantMethod, tc.wantPath)
			}
		})
	}
}

// TestIAMPolicySpecYAML_TravelsAsText pins the spec_yaml wire shape: the
// server's request and reply carry it as a YAML string, while the proto
// carries bytes, which encoding/json would send as base64.
func TestIAMPolicySpecYAML_TravelsAsText(t *testing.T) {
	const yaml = "rules:\n  - effect: allow\n    actions: [read]\n"
	created := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)

	writes := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
	}{
		{"CreatePolicy", platformv1.PlatformIAMService_CreatePolicy_FullMethodName,
			&platformv1.CreateIAMPolicyRequest{TenantId: "t1", Name: "p1", Priority: 5, SpecYaml: []byte(yaml)},
			&platformv1.IAMPolicyResponse{}},
		{"UpdatePolicy", platformv1.PlatformIAMService_UpdatePolicy_FullMethodName,
			&platformv1.UpdateIAMPolicyRequest{TenantId: "t1", PolicyName: "p1", Priority: 5, SpecYaml: []byte(yaml)},
			&platformv1.IAMPolicyResponse{}},
		{"ValidatePolicy", platformv1.PlatformIAMService_ValidatePolicy_FullMethodName,
			&platformv1.ValidateIAMPolicyRequest{TenantId: "t1", SpecYaml: []byte(yaml)},
			&platformv1.ValidateIAMPolicyResponse{}},
	}
	for _, tc := range writes {
		t.Run(tc.name+"/request", func(t *testing.T) {
			var body map[string]interface{}
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health/live" {
					w.WriteHeader(http.StatusOK)
					return
				}
				raw, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Errorf("request body %q is not JSON: %v", raw, err)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			})
			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if got := body["spec_yaml"]; got != yaml {
				t.Errorf("body spec_yaml = %#v, want the raw YAML %q", got, yaml)
			}
			if _, ok := body["tenant_id"]; ok {
				t.Errorf("body carries tenant_id %v; the tenant travels in the path", body["tenant_id"])
			}
			if _, ok := body["policy_name"]; ok {
				t.Errorf("body carries policy_name %v; the name travels in the path", body["policy_name"])
			}
		})
	}

	replies := []struct {
		name       string
		grpcMethod string
		req        proto.Message
	}{
		{"CreatePolicy", platformv1.PlatformIAMService_CreatePolicy_FullMethodName,
			&platformv1.CreateIAMPolicyRequest{TenantId: "t1", Name: "p1", SpecYaml: []byte(yaml)}},
		{"GetPolicy", platformv1.PlatformIAMService_GetPolicy_FullMethodName,
			&platformv1.GetIAMPolicyRequest{TenantId: "t1", PolicyName: "p1"}},
		{"UpdatePolicy", platformv1.PlatformIAMService_UpdatePolicy_FullMethodName,
			&platformv1.UpdateIAMPolicyRequest{TenantId: "t1", PolicyName: "p1", SpecYaml: []byte(yaml)}},
	}
	bare, err := json.Marshal(map[string]interface{}{
		"name": "p1", "tenant_id": "t1", "description": "readers", "priority": 5,
		"spec_yaml": yaml, "labels": map[string]string{"team": "docs"},
		"created_at": created, "updated_at": created,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range replies {
		t.Run(tc.name+"/reply", func(t *testing.T) {
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health/live" {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(bare)
			})
			resp := &platformv1.IAMPolicyResponse{}
			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			policy := resp.GetPolicy()
			if policy == nil {
				t.Fatal("reply has no policy: the bare PolicyResponse was not placed under policy")
			}
			if string(policy.GetSpecYaml()) != yaml {
				t.Errorf("SpecYaml = %q, want %q", policy.GetSpecYaml(), yaml)
			}
			if policy.GetName() != "p1" || policy.GetTenantId() != "t1" || policy.GetDescription() != "readers" ||
				policy.GetPriority() != 5 || policy.GetLabels()["team"] != "docs" {
				t.Errorf("policy = %v", policy)
			}
			if !policy.GetCreatedAt().AsTime().Equal(created) || !policy.GetUpdatedAt().AsTime().Equal(created) {
				t.Errorf("timestamps = %v / %v, want %v", policy.GetCreatedAt(), policy.GetUpdatedAt(), created)
			}
		})
	}
}

// TestIAMPolicyMissingName_RejectedBeforeTheWire: a policy RPC with no tenant,
// or an item RPC with no policy name, is refused InvalidArgument before the
// request leaves the client, never sent to a shorter path.
func TestIAMPolicyMissingName_RejectedBeforeTheWire(t *testing.T) {
	cases := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
	}{
		{"GetPolicy/no name", platformv1.PlatformIAMService_GetPolicy_FullMethodName,
			&platformv1.GetIAMPolicyRequest{TenantId: "t1"}, &platformv1.IAMPolicyResponse{}},
		{"UpdatePolicy/no name", platformv1.PlatformIAMService_UpdatePolicy_FullMethodName,
			&platformv1.UpdateIAMPolicyRequest{TenantId: "t1"}, &platformv1.IAMPolicyResponse{}},
		{"DeletePolicy/no name", platformv1.PlatformIAMService_DeletePolicy_FullMethodName,
			&platformv1.DeleteIAMPolicyRequest{TenantId: "t1"}, &platformv1.DeleteIAMPolicyResponse{}},
	}
	for _, call := range iamPolicyCalls() {
		zero := proto.Clone(call.req)
		zero.ProtoReflect().Clear(zero.ProtoReflect().Descriptor().Fields().ByName("tenant_id"))
		cases = append(cases, struct {
			name       string
			grpcMethod string
			req        proto.Message
			resp       proto.Message
		}{call.name + "/no tenant", call.grpcMethod, zero, call.resp})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var apiHits int
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health/live" {
					apiHits++
				}
				w.WriteHeader(http.StatusOK)
			})

			err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp)
			if err == nil {
				t.Fatal("expected an error for the missing identifier, got nil")
			}
			if st, _ := status.FromError(err); st == nil || st.Code() != codes.InvalidArgument {
				t.Errorf("status = %v, want InvalidArgument", st)
			}
			if apiHits != 0 {
				t.Errorf("server saw %d API hits; want 0 -- the request must not leave the client", apiHits)
			}
		})
	}
}

// TestIAMListPolicies_PaginationTravelsAsLimitAndOffset pins the list
// route's paging: the server reads only ?limit= and ?offset=
// (pkg/webservice/v1/rest/iam getPaginationParams), with 1-based pages,
// so page 2 of 7 is limit=7&offset=7. No pagination sends no query.
func TestIAMListPolicies_PaginationTravelsAsLimitAndOffset(t *testing.T) {
	cases := []struct {
		name       string
		pagination *platformv1.PaginationRequest
		wantQuery  string
	}{
		{"page2", &platformv1.PaginationRequest{Page: 2, PageSize: 7}, "limit=7&offset=7"},
		{"page1", &platformv1.PaginationRequest{Page: 1, PageSize: 7}, "limit=7"},
		{"absent", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotQuery string
			var gotBody []byte
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health/live" {
					w.WriteHeader(http.StatusOK)
					return
				}
				gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
				gotBody, _ = io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			})
			req := &platformv1.ListIAMPoliciesRequest{TenantId: "t1", Pagination: tc.pagination}
			if err := a.Connection().Invoke(context.Background(),
				platformv1.PlatformIAMService_ListPolicies_FullMethodName, req, &platformv1.ListIAMPoliciesResponse{}); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if gotPath != "/api/v1/iam/tenants/t1/policies" {
				t.Errorf("path = %q", gotPath)
			}
			if gotQuery != tc.wantQuery {
				t.Errorf("query = %q, want %q", gotQuery, tc.wantQuery)
			}
			if len(gotBody) > 0 {
				var body map[string]interface{}
				if err := json.Unmarshal(gotBody, &body); err == nil {
					if _, ok := body["pagination"]; ok {
						t.Errorf("body carries pagination %v; it travels in the query", body["pagination"])
					}
				}
			}
		})
	}
}
