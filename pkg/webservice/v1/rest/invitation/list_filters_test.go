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

package invitation

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestListInvitations_PassesTheQueryFilters: the status, email and
// pending_only query parameters the JS SDK sends reach the service as the
// request's filters, next to the session tenant.
func TestListInvitations_PassesTheQueryFilters(t *testing.T) {
	srv := &fakeInvitationServer{}
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/invitations?status=pending&email=example.com&pending_only=true", nil)
	req = withSession(req, "caller-tenant", "42")

	rec := serve(srv, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	want := &platformv1.ListInvitationsRequest{
		TenantId:     "caller-tenant",
		StatusFilter: platformv1.InvitationStatus_INVITATION_STATUS_PENDING,
		EmailFilter:  "example.com",
		PendingOnly:  true,
	}
	assert.True(t, proto.Equal(want, srv.last), "service received %v, want %v", srv.last, want)
}

// TestListInvitations_StatusNames: the short status names in any case and
// the full proto enum names map to the matching InvitationStatus.
func TestListInvitations_StatusNames(t *testing.T) {
	for raw, want := range map[string]platformv1.InvitationStatus{
		"accepted":                  platformv1.InvitationStatus_INVITATION_STATUS_ACCEPTED,
		"expired":                   platformv1.InvitationStatus_INVITATION_STATUS_EXPIRED,
		"revoked":                   platformv1.InvitationStatus_INVITATION_STATUS_REVOKED,
		"REVOKED":                   platformv1.InvitationStatus_INVITATION_STATUS_REVOKED,
		"INVITATION_STATUS_EXPIRED": platformv1.InvitationStatus_INVITATION_STATUS_EXPIRED,
	} {
		t.Run(raw, func(t *testing.T) {
			srv := &fakeInvitationServer{}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations?status="+raw, nil)
			req = withSession(req, "caller-tenant", "42")

			rec := serve(srv, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			got, ok := srv.last.(*platformv1.ListInvitationsRequest)
			require.True(t, ok, "service received %T", srv.last)
			assert.Equal(t, want, got.GetStatusFilter())
		})
	}
}

// TestListInvitations_BadFilterIs400: an unknown status or an unparsable
// pending_only is refused before the service is called.
func TestListInvitations_BadFilterIs400(t *testing.T) {
	for _, query := range []string{"status=bogus", "pending_only=maybe"} {
		t.Run(query, func(t *testing.T) {
			srv := &fakeInvitationServer{}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations?"+query, nil)
			req = withSession(req, "caller-tenant", "42")

			rec := serve(srv, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Nil(t, srv.last, "a bad filter reached the service")
		})
	}
}
