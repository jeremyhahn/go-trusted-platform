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
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRoleListClient serves pages of roles keyed by page token.
type fakeRoleListClient struct {
	pages    map[string]*iam.ListRolesResponse
	err      error
	tenants  []string
	tokens   []string
	requests []*iam.ListRolesRequest
}

func (f *fakeRoleListClient) List(_ context.Context, tenantID string, req *iam.ListRolesRequest) (*iam.ListRolesResponse, error) {
	f.tenants = append(f.tenants, tenantID)
	f.tokens = append(f.tokens, req.PageToken)
	f.requests = append(f.requests, req)
	if f.err != nil {
		return nil, f.err
	}
	return f.pages[req.PageToken], nil
}

func rolePage(next string, names ...string) *iam.ListRolesResponse {
	resp := &iam.ListRolesResponse{Pagination: iam.PaginationInfo{NextPageToken: next, HasMore: next != ""}}
	for _, n := range names {
		resp.Roles = append(resp.Roles, iam.Role{Name: n})
	}
	return resp
}

// TestInvitationRoleLister_ReadsEveryPage verifies the adapter returns the
// names from every page of the tenant's IAM role list, system roles included
// (#1992).
func TestInvitationRoleLister_ReadsEveryPage(t *testing.T) {
	client := &fakeRoleListClient{pages: map[string]*iam.ListRolesResponse{
		"":   rolePage("p2", "admin", "member"),
		"p2": rolePage("p3", "viewer"),
		"p3": rolePage("", "auditor"),
	}}

	names, err := newInvitationRoleLister(client).RoleNames(context.Background(), "tenant-a")

	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "member", "viewer", "auditor"}, names)
	assert.Equal(t, []string{"", "p2", "p3"}, client.tokens)
	assert.Equal(t, []string{"tenant-a", "tenant-a", "tenant-a"}, client.tenants)
	for _, req := range client.requests {
		assert.True(t, req.IncludeSystem)
	}
}

// TestInvitationRoleLister_StopsOnRepeatedToken verifies a server that hands
// back the same page token does not loop the adapter forever.
func TestInvitationRoleLister_StopsOnRepeatedToken(t *testing.T) {
	client := &fakeRoleListClient{pages: map[string]*iam.ListRolesResponse{
		"":   rolePage("p2", "admin"),
		"p2": rolePage("p2", "member"),
	}}

	names, err := newInvitationRoleLister(client).RoleNames(context.Background(), "tenant-a")

	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "member"}, names)
	assert.Equal(t, []string{"", "p2"}, client.tokens)
}

// TestInvitationRoleLister_NilPageStops verifies an empty response ends the
// listing.
func TestInvitationRoleLister_NilPageStops(t *testing.T) {
	client := &fakeRoleListClient{pages: map[string]*iam.ListRolesResponse{}}

	names, err := newInvitationRoleLister(client).RoleNames(context.Background(), "tenant-a")

	require.NoError(t, err)
	assert.Empty(t, names)
	assert.Equal(t, []string{""}, client.tokens)
}

// TestInvitationRoleLister_ListError verifies a failed list call is returned.
func TestInvitationRoleLister_ListError(t *testing.T) {
	cause := errors.New("iam unavailable")
	client := &fakeRoleListClient{err: cause}

	names, err := newInvitationRoleLister(client).RoleNames(context.Background(), "tenant-a")

	require.ErrorIs(t, err, cause)
	assert.Nil(t, names)
}

// TestWireInvitationRoleLister_NoIAMClientLeavesCreateRefused verifies the
// daemon wiring tolerates a disabled IAM service: no lister is set, so the
// invitation service still refuses Create instead of accepting any role.
func TestWireInvitationRoleLister_NoIAMClientLeavesCreateRefused(t *testing.T) {
	svc := platformservice.NewInvitationService(logging.NewLogger(slog.LevelWarn, os.Stderr), nil, nil)

	wireInvitationRoleLister(nil, svc, nil)

	_, err := svc.Create(context.Background(), &platformservice.CreateInvitationRequest{
		TenantID: "tenant-a", Email: "a@example.com", Role: "member", InvitedByID: 1,
	})
	var unavailable platformservice.ErrInvitationRolesUnavailable
	require.ErrorAs(t, err, &unavailable)
}
