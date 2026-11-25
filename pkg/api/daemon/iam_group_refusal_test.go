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

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TestMCPIAMGroupToolsRefuse asserts every MCP group tool answers ErrIAMGroupsNotSupported.
func TestMCPIAMGroupToolsRefuse(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	ctx := context.Background()
	page := mcp.IAMPagination{Page: 1, PageSize: 10}
	calls := map[string]func() (interface{}, error){
		"CreateGroup": func() (interface{}, error) {
			return provider.IAMCreateGroup(ctx, &mcp.IAMCreateGroupRequest{TenantID: "t1", ID: "g1"})
		},
		"DeleteGroup": func() (interface{}, error) { return provider.IAMDeleteGroup(ctx, "t1", "g1") },
		"GetGroup":    func() (interface{}, error) { return provider.IAMGetGroup(ctx, "t1", "g1") },
		"UpdateGroup": func() (interface{}, error) {
			return provider.IAMUpdateGroup(ctx, &mcp.IAMUpdateGroupRequest{TenantID: "t1", GroupID: "g1", Name: "n"})
		},
		"ListGroups":        func() (interface{}, error) { return provider.IAMListGroups(ctx, "t1", page) },
		"AddGroupMember":    func() (interface{}, error) { return provider.IAMAddGroupMember(ctx, "t1", "g1", "u1") },
		"RemoveGroupMember": func() (interface{}, error) { return provider.IAMRemoveGroupMember(ctx, "t1", "g1", "u1") },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			_, err := call()
			var refused ErrIAMGroupsNotSupported
			if !errors.As(err, &refused) {
				t.Fatalf("err = %v, want ErrIAMGroupsNotSupported", err)
			}
			if refused.Operation != name {
				t.Fatalf("operation = %q, want %q", refused.Operation, name)
			}
		})
	}
}

// TestQUICIAMGroupOpcodesRefuse asserts every QUIC group opcode and the group-update sub answer not-implemented groups.
func TestQUICIAMGroupOpcodesRefuse(t *testing.T) {
	handler := newTestQUICServiceHandler(logging.DefaultLogger())
	handler.SetIAMGRPCService(wiredIAMGRPCService(newMemIAM()))

	cases := map[string]*quicwire.Request{
		"CreateGroup": iamDirectRequest(t, quicwire.OpIAMGroupCreate,
			&platformv1.CreateIAMGroupRequest{TenantId: "acme", Id: "g1"}),
		"DeleteGroup": iamDirectRequest(t, quicwire.OpIAMGroupDelete,
			&platformv1.DeleteIAMGroupRequest{TenantId: "acme", GroupId: "g1"}),
		"GetGroup": iamDirectRequest(t, quicwire.OpIAMGroupGet,
			&platformv1.GetIAMGroupRequest{TenantId: "acme", GroupId: "g1"}),
		"ListGroups": iamDirectRequest(t, quicwire.OpIAMGroupList,
			&platformv1.ListIAMGroupsRequest{TenantId: "acme"}),
		"AddGroupMember": iamDirectRequest(t, quicwire.OpIAMGroupAddMember,
			&platformv1.AddGroupMemberRequest{TenantId: "acme", GroupId: "g1", UserId: "u1"}),
		"RemoveGroupMember": iamDirectRequest(t, quicwire.OpIAMGroupRemoveMember,
			&platformv1.RemoveGroupMemberRequest{TenantId: "acme", GroupId: "g1", UserId: "u1"}),
		"UpdateGroup": iamCategoryRequest(t, quicwire.IAMSubGroupUpdate,
			&platformv1.UpdateIAMGroupRequest{TenantId: "acme", GroupId: "g1"}),
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			resp := handler.HandleRequest(context.Background(), req)
			if resp.Status != quicwire.StatusNotImplemented {
				t.Fatalf("status = 0x%02x, want NotImplemented (payload %q)", resp.Status, resp.Payload)
			}
			want := ErrIAMGroupsNotSupported{Operation: name}.Error()
			if !strings.Contains(string(resp.Payload), want) {
				t.Fatalf("payload %q does not carry %q", resp.Payload, want)
			}
		})
	}
}
