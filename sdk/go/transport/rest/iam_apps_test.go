package rest

import (
	"context"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// iamAppRouteCase is one IAM app method sent over REST: the request it
// carries, the method and path the webservice serves it on
// (pkg/webservice/v1/rest/iam/router.go, registerAppRoutes) and the reply
// the server answers with.
type iamAppRouteCase struct {
	name       string
	grpcMethod string
	req        proto.Message
	resp       proto.Message
	wantMethod string
	wantPath   string
	reply      string
}

func iamAppRouteCases() []iamAppRouteCase {
	return []iamAppRouteCase{
		{
			name:       "RegisterApp",
			grpcMethod: platformv1.PlatformIAMService_RegisterApp_FullMethodName,
			req:        &platformv1.RegisterIAMAppRequest{TenantId: "t1", Name: "app"},
			resp:       &platformv1.IAMAppResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/iam/tenants/t1/apps",
			reply:      `{"client_id":"c1","tenant_id":"t1","name":"app"}`,
		},
		{
			name:       "ListApps",
			grpcMethod: platformv1.PlatformIAMService_ListApps_FullMethodName,
			req:        &platformv1.ListIAMAppsRequest{TenantId: "t1"},
			resp:       &platformv1.ListIAMAppsResponse{},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/iam/tenants/t1/apps",
			reply:      `{"apps":[{"client_id":"c1","name":"app"}],"total":"1"}`,
		},
		{
			name:       "GetApp",
			grpcMethod: platformv1.PlatformIAMService_GetApp_FullMethodName,
			req:        &platformv1.GetIAMAppRequest{TenantId: "t1", ClientId: "c1"},
			resp:       &platformv1.IAMAppResponse{},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/iam/tenants/t1/apps/c1",
			reply:      `{"client_id":"c1","tenant_id":"t1","name":"app"}`,
		},
		{
			name:       "UpdateApp",
			grpcMethod: platformv1.PlatformIAMService_UpdateApp_FullMethodName,
			req:        &platformv1.UpdateIAMAppRequest{TenantId: "t1", ClientId: "c1", Name: "app"},
			resp:       &platformv1.IAMAppResponse{},
			wantMethod: http.MethodPut,
			wantPath:   "/api/v1/iam/tenants/t1/apps/c1",
			reply:      `{"client_id":"c1","tenant_id":"t1","name":"app"}`,
		},
		{
			name:       "DeleteApp",
			grpcMethod: platformv1.PlatformIAMService_DeleteApp_FullMethodName,
			req:        &platformv1.DeleteIAMAppRequest{TenantId: "t1", ClientId: "c1"},
			resp:       &platformv1.DeleteIAMAppResponse{},
			wantMethod: http.MethodDelete,
			wantPath:   "/api/v1/iam/tenants/t1/apps/c1",
			reply:      `{"status":{"success":true}}`,
		},
		{
			name:       "RotateAppSecret",
			grpcMethod: platformv1.PlatformIAMService_RotateAppSecret_FullMethodName,
			req:        &platformv1.RotateIAMAppSecretRequest{TenantId: "t1", ClientId: "c1"},
			resp:       &platformv1.RotateIAMAppSecretResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/iam/tenants/t1/apps/c1/rotate",
			reply:      `{"client_id":"c1","name":"app","client_secret":"s3"}`,
		},
	}
}

// TestIAMAppRoutes_ResolveToTheServedTenantRoutes: each app method reaches
// the tenant-scoped route the webservice serves, with the tenant and the
// client id in the path. Without a route the adapter derived POST
// /api/v1/platformiam/<method>, which no server serves (#1957).
func TestIAMAppRoutes_ResolveToTheServedTenantRoutes(t *testing.T) {
	for _, tc := range iamAppRouteCases() {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod, gotPath string
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health/live" {
					w.WriteHeader(http.StatusOK)
					return
				}
				gotMethod, gotPath = r.Method, r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.reply))
			})

			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if gotMethod != tc.wantMethod || gotPath != tc.wantPath {
				t.Errorf("sent %s %s, want %s %s", gotMethod, gotPath, tc.wantMethod, tc.wantPath)
			}
		})
	}
}

// TestIAMAppReplies_DecodeIntoTheProtoResponse: the bare app the server
// answers Register, Get and Update with lands in IAMAppResponse.App, and
// the bare rotate reply fills RotateIAMAppSecretResponse.
func TestIAMAppReplies_DecodeIntoTheProtoResponse(t *testing.T) {
	for _, tc := range iamAppRouteCases() {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.reply))
			})
			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			switch resp := tc.resp.(type) {
			case *platformv1.IAMAppResponse:
				if resp.GetApp().GetClientId() != "c1" || resp.GetApp().GetName() != "app" {
					t.Errorf("app = %v, want client_id c1 and name app", resp.GetApp())
				}
			case *platformv1.ListIAMAppsResponse:
				if len(resp.GetApps()) != 1 || resp.GetApps()[0].GetClientId() != "c1" {
					t.Errorf("apps = %v, want one app c1", resp.GetApps())
				}
			case *platformv1.DeleteIAMAppResponse:
				if !resp.GetStatus().GetSuccess() {
					t.Errorf("status = %v, want success", resp.GetStatus())
				}
			case *platformv1.RotateIAMAppSecretResponse:
				if resp.GetClientId() != "c1" || resp.GetName() != "app" || resp.GetClientSecret() != "s3" {
					t.Errorf("rotate = %v, want c1, app and the new secret", resp)
				}
			}
		})
	}
}

// TestIAMAppMissingClientID_RejectedBeforeTheWire: a missing tenant or
// client id is refused with InvalidArgument and never reaches the server,
// which would otherwise see a shorter path (a collection) or an empty
// segment.
func TestIAMAppMissingClientID_RejectedBeforeTheWire(t *testing.T) {
	cases := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
	}{
		{"GetApp", platformv1.PlatformIAMService_GetApp_FullMethodName,
			&platformv1.GetIAMAppRequest{TenantId: "t1"}, &platformv1.IAMAppResponse{}},
		{"UpdateApp", platformv1.PlatformIAMService_UpdateApp_FullMethodName,
			&platformv1.UpdateIAMAppRequest{TenantId: "t1", Name: "app"}, &platformv1.IAMAppResponse{}},
		{"DeleteApp", platformv1.PlatformIAMService_DeleteApp_FullMethodName,
			&platformv1.DeleteIAMAppRequest{TenantId: "t1"}, &platformv1.DeleteIAMAppResponse{}},
		{"RotateAppSecret", platformv1.PlatformIAMService_RotateAppSecret_FullMethodName,
			&platformv1.RotateIAMAppSecretRequest{TenantId: "t1"}, &platformv1.RotateIAMAppSecretResponse{}},
		{"RegisterApp no tenant", platformv1.PlatformIAMService_RegisterApp_FullMethodName,
			&platformv1.RegisterIAMAppRequest{Name: "app"}, &platformv1.IAMAppResponse{}},
		{"ListApps no tenant", platformv1.PlatformIAMService_ListApps_FullMethodName,
			&platformv1.ListIAMAppsRequest{}, &platformv1.ListIAMAppsResponse{}},
		{"GetApp no tenant", platformv1.PlatformIAMService_GetApp_FullMethodName,
			&platformv1.GetIAMAppRequest{ClientId: "c1"}, &platformv1.IAMAppResponse{}},
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

// The IAM handlers read pagination only from limit/offset query params,
// so a non-default page must reach the URL, not the GET body.
func TestIAMListApps_SendsPaginationAsLimitAndOffset(t *testing.T) {
	cases := []struct {
		name      string
		page      *platformv1.PaginationRequest
		wantQuery string
	}{
		{"second page", &platformv1.PaginationRequest{Page: 2, PageSize: 7}, "limit=7&offset=7"},
		{"third page", &platformv1.PaginationRequest{Page: 3, PageSize: 7}, "limit=7&offset=14"},
		{"first page", &platformv1.PaginationRequest{Page: 1, PageSize: 7}, "limit=7"},
		{"no pagination", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotQuery string
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/iam/tenants/t1/apps" {
					gotQuery = r.URL.RawQuery
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"apps":[],"total":"0"}`))
			})
			req := &platformv1.ListIAMAppsRequest{TenantId: "t1", Pagination: tc.page}
			if err := a.Connection().Invoke(context.Background(),
				platformv1.PlatformIAMService_ListApps_FullMethodName, req, &platformv1.ListIAMAppsResponse{}); err != nil {
				t.Fatalf("ListApps: %v", err)
			}
			if gotQuery != tc.wantQuery {
				t.Errorf("query = %q, want %q", gotQuery, tc.wantQuery)
			}
		})
	}
}
