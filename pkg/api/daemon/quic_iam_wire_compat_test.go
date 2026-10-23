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

//go:build codec_msgpack

package daemon

import (
	"testing"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// The tests in this file guard the QUIC wire contract for the IAM surface
// between the platform SDK client and the daemon. The SDK QUIC transport maps
// each /platform.v1.PlatformIAMService/* RPC onto an OpIAM* opcode and hands
// the generated pb request struct straight to the payload codec (keyed on
// exact Go field names). Before the pb-wire fix the daemon decoded flat local
// structs (CreateUserRequest, GetUserRequest, ...) whose Go field names did
// not match the pb Go field names, silently dropping every diverging field:
//
//   - every tenant_id field   (flat TenantID -> pb TenantId    -> dropped)
//   - every user/role/group id (flat UserID   -> pb UserId      -> dropped)
//   - CreateIAMUserRequest.Roles / Groups (never present on the flat struct)
//
// Each message is round-tripped through the payload codec and compared with
// proto.Equal so a codec or field-shape regression fails here first.

func roundTripIAMWire(t *testing.T, src, dst proto.Message) {
	t.Helper()
	payload, err := quicwire.EncodePayload(src)
	if err != nil {
		t.Fatalf("encode %T: %v", src, err)
	}
	if err := quicwire.DecodePayload(payload, dst); err != nil {
		t.Fatalf("decode %T into %T: %v", src, dst, err)
	}
	if !proto.Equal(src, dst) {
		t.Fatalf("round trip mismatch:\n src: %+v\n dst: %+v", src, dst)
	}
}

func TestQUICIAMWireCompatUser(t *testing.T) {
	// Create carries Roles/Groups that the flat CreateUserRequest never had a
	// field for, plus the TenantId the flat TenantID dropped.
	roundTripIAMWire(t,
		&platformv1.CreateIAMUserRequest{
			TenantId:   "tenant-a",
			Email:      "user@example.com",
			Name:       "Example User",
			Roles:      []string{"role-admin", "role-viewer"},
			Groups:     []string{"group-ops"},
			Attributes: map[string]string{"dept": "eng"},
		},
		&platformv1.CreateIAMUserRequest{})
	roundTripIAMWire(t,
		&platformv1.GetIAMUserRequest{TenantId: "tenant-a", UserId: "user-1"},
		&platformv1.GetIAMUserRequest{})
	roundTripIAMWire(t,
		&platformv1.ListIAMUsersRequest{
			TenantId:    "tenant-a",
			Pagination:  &platformv1.PaginationRequest{Page: 2, PageSize: 25},
			EmailFilter: "@example.com",
			RoleFilter:  "role-admin",
			GroupFilter: "group-ops",
		},
		&platformv1.ListIAMUsersRequest{})
	roundTripIAMWire(t,
		&platformv1.UpdateIAMUserRequest{
			TenantId:   "tenant-a",
			UserId:     "user-1",
			Email:      "new@example.com",
			Name:       "Renamed User",
			Roles:      []string{"role-admin"},
			Groups:     []string{"group-sre"},
			Attributes: map[string]string{"dept": "sre"},
		},
		&platformv1.UpdateIAMUserRequest{})
	roundTripIAMWire(t,
		&platformv1.DeleteIAMUserRequest{TenantId: "tenant-a", UserId: "user-1"},
		&platformv1.DeleteIAMUserRequest{})
}

func TestQUICIAMWireCompatRole(t *testing.T) {
	roundTripIAMWire(t,
		&platformv1.CreateIAMRoleRequest{
			TenantId:    "tenant-a",
			Id:          "role-admin",
			Name:        "Administrator",
			Description: "full access",
			Permissions: []string{"users:read", "users:write"},
		},
		&platformv1.CreateIAMRoleRequest{})
	roundTripIAMWire(t,
		&platformv1.GetIAMRoleRequest{TenantId: "tenant-a", RoleId: "role-admin"},
		&platformv1.GetIAMRoleRequest{})
	roundTripIAMWire(t,
		&platformv1.ListIAMRolesRequest{
			TenantId:   "tenant-a",
			Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 50},
		},
		&platformv1.ListIAMRolesRequest{})
	roundTripIAMWire(t,
		&platformv1.DeleteIAMRoleRequest{TenantId: "tenant-a", RoleId: "role-admin"},
		&platformv1.DeleteIAMRoleRequest{})
	roundTripIAMWire(t,
		&platformv1.AssignIAMRoleRequest{TenantId: "tenant-a", UserId: "user-1", RoleId: "role-admin"},
		&platformv1.AssignIAMRoleRequest{})
	roundTripIAMWire(t,
		&platformv1.RevokeIAMRoleRequest{TenantId: "tenant-a", UserId: "user-1", RoleId: "role-admin"},
		&platformv1.RevokeIAMRoleRequest{})
}

func TestQUICIAMWireCompatGroup(t *testing.T) {
	roundTripIAMWire(t,
		&platformv1.CreateIAMGroupRequest{
			TenantId:    "tenant-a",
			Id:          "group-ops",
			Name:        "Operations",
			Description: "ops team",
		},
		&platformv1.CreateIAMGroupRequest{})
	roundTripIAMWire(t,
		&platformv1.GetIAMGroupRequest{TenantId: "tenant-a", GroupId: "group-ops"},
		&platformv1.GetIAMGroupRequest{})
	roundTripIAMWire(t,
		&platformv1.ListIAMGroupsRequest{TenantId: "tenant-a"},
		&platformv1.ListIAMGroupsRequest{})
	roundTripIAMWire(t,
		&platformv1.DeleteIAMGroupRequest{TenantId: "tenant-a", GroupId: "group-ops"},
		&platformv1.DeleteIAMGroupRequest{})
	roundTripIAMWire(t,
		&platformv1.AddGroupMemberRequest{TenantId: "tenant-a", GroupId: "group-ops", UserId: "user-1"},
		&platformv1.AddGroupMemberRequest{})
	roundTripIAMWire(t,
		&platformv1.RemoveGroupMemberRequest{TenantId: "tenant-a", GroupId: "group-ops", UserId: "user-1"},
		&platformv1.RemoveGroupMemberRequest{})
}

func TestQUICIAMWireCompatPermissionAndToken(t *testing.T) {
	roundTripIAMWire(t,
		&platformv1.CheckIAMPermissionRequest{
			TenantId:   "tenant-a",
			SubjectId:  "user-1",
			Roles:      []string{"role-admin"},
			Groups:     []string{"group-ops"},
			Action:     "read",
			Resource:   "document:123",
			Context:    map[string]string{"ip": "10.0.0.1"},
			Attributes: map[string]string{"mfa": "true"},
		},
		&platformv1.CheckIAMPermissionRequest{})
	// Token ops are wire-mapped even though the daemon delegate returns
	// Unimplemented (OIDC handles tokens); the request shape must still
	// round-trip so the SDK reaches the daemon before the honest
	// StatusNotImplemented reply.
	roundTripIAMWire(t,
		&platformv1.CreateIAMTokenRequest{
			TenantId:  "tenant-a",
			UserId:    "user-1",
			Scopes:    []string{"openid", "profile"},
			ExpiresIn: 3600,
		},
		&platformv1.CreateIAMTokenRequest{})
}
