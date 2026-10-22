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

package iam

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeIAMServiceClient records the ListUsers request it is sent.
type fakeIAMServiceClient struct {
	platformv1.PlatformIAMServiceClient

	listReq  *platformv1.ListIAMUsersRequest
	listResp *platformv1.ListIAMUsersResponse
	listErr  error
}

func (f *fakeIAMServiceClient) ListUsers(_ context.Context, req *platformv1.ListIAMUsersRequest, _ ...grpc.CallOption) (*platformv1.ListIAMUsersResponse, error) {
	f.listReq = req
	return f.listResp, f.listErr
}

func TestClient_ListUsersDomain_SendsPageAndFilter(t *testing.T) {
	fake := &fakeIAMServiceClient{listResp: &platformv1.ListIAMUsersResponse{
		Users: []*platformv1.IAMUser{{Id: "u-1", Email: "alice@acme.test"}},
		Total: 1,
	}}
	filter := UserListFilter{Email: "alice", Role: "role-admin", Group: "group-ops"}

	result, err := NewClientFromGRPC(fake).ListUsersDomain(context.Background(), "acme", 2, 25, filter)
	if err != nil {
		t.Fatalf("ListUsersDomain: %v", err)
	}

	req := fake.listReq
	if req.GetTenantId() != "acme" || req.GetPagination().GetPage() != 2 || req.GetPagination().GetPageSize() != 25 {
		t.Errorf("request = %v, want tenant acme, page 2, page size 25", req)
	}
	if req.GetEmailFilter() != "alice" || req.GetRoleFilter() != "role-admin" || req.GetGroupFilter() != "group-ops" {
		t.Errorf("filters = %q/%q/%q, want alice/role-admin/group-ops",
			req.GetEmailFilter(), req.GetRoleFilter(), req.GetGroupFilter())
	}
	if result.Total != 1 || len(result.Users) != 1 || result.Users[0].ID != "u-1" {
		t.Errorf("result = %+v, want the one user u-1", result)
	}
}

func TestClient_ListUsersDomain_Error(t *testing.T) {
	fake := &fakeIAMServiceClient{listErr: status.Error(codes.PermissionDenied, "iam:read required")}

	_, err := NewClientFromGRPC(fake).ListUsersDomain(context.Background(), "acme", 1, 50, UserListFilter{})

	var typed *ErrListUsersFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *ErrListUsersFailed", err)
	}
	if status.Code(errors.Unwrap(err)) != codes.PermissionDenied {
		t.Errorf("cause = %v, want the transport status preserved", errors.Unwrap(err))
	}
}
