// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package attestation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict/feed"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// verdictPoller records each poll and answers page, or err when set.
type verdictPoller struct {
	page      *platformv1.PollDeviceVerdictsResponse
	err       error
	audiences []feed.Audience
	requests  []*platformv1.PollDeviceVerdictsRequest
}

func (p *verdictPoller) PollDeviceVerdictsFor(_ context.Context, audience feed.Audience, req *platformv1.PollDeviceVerdictsRequest) (*platformv1.PollDeviceVerdictsResponse, error) {
	p.audiences = append(p.audiences, audience)
	p.requests = append(p.requests, req)
	return p.page, p.err
}

func mountVerdicts(poller VerdictPoller) *mux.Router {
	root := mux.NewRouter()
	NewVerdictsRouter(poller, testWriter()).RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

// pollVerdicts sends GET /api/v1/attestation/verdicts?query as a caller whose
// verified session names tenantID; an empty tenantID sends no session.
func pollVerdicts(router *mux.Router, tenantID, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/verdicts?"+query, nil)
	if tenantID != "" {
		session := iammw.NewIAMSession(&iamsdk.User{ID: "u1", TenantID: tenantID})
		req = req.WithContext(iammw.SetSessionInContext(req.Context(), session))
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestVerdictsRouter_PollsForTheSessionTenant pins the REST long-poll: the
// cursor and wait reach the feed as given, the session's tenant decides what
// the caller sees, and the page is the pb reply as protojson in the envelope.
func TestVerdictsRouter_PollsForTheSessionTenant(t *testing.T) {
	poller := &verdictPoller{page: &platformv1.PollDeviceVerdictsResponse{
		Cursor:   "18f.4",
		Verdicts: []*platformv1.DeviceVerdictEvent{{EventId: "ev-1", DeviceId: 7, TenantId: "tenant-a"}},
	}}
	w := pollVerdicts(mountVerdicts(poller), "tenant-a", "cursor=18f.3&wait_ms=2500")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	require.Len(t, poller.requests, 1)
	assert.Equal(t, "18f.3", poller.requests[0].GetCursor())
	assert.Equal(t, uint32(2500), poller.requests[0].GetWaitMs())
	assert.True(t, poller.audiences[0].Admits("tenant-a"))
	assert.False(t, poller.audiences[0].Admits("tenant-b"), "a tenant session must not see another tenant's verdicts")

	payload := decodeEnvelope(t, w)["payload"].(map[string]any)
	assert.Equal(t, "18f.4", payload["cursor"])
	verdicts := payload["verdicts"].([]any)
	require.Len(t, verdicts, 1)
	assert.Equal(t, "ev-1", verdicts[0].(map[string]any)["eventId"])
}

func TestVerdictsRouter_PlatformSessionSeesEveryTenant(t *testing.T) {
	poller := &verdictPoller{page: &platformv1.PollDeviceVerdictsResponse{Cursor: "18f.0"}}
	w := pollVerdicts(mountVerdicts(poller), feed.PlatformTenantID, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.True(t, poller.audiences[0].Admits("tenant-b"))
}

func TestVerdictsRouter_Refusals(t *testing.T) {
	tests := []struct {
		name   string
		poller VerdictPoller
		tenant string
		query  string
		want   int
	}{
		{name: "no feed on this node", poller: nil, tenant: "tenant-a", want: http.StatusServiceUnavailable},
		{name: "no session tenant", poller: &verdictPoller{}, tenant: "", want: http.StatusForbidden},
		{name: "malformed wait", poller: &verdictPoller{}, tenant: "tenant-a", query: "wait_ms=soon", want: http.StatusBadRequest},
		{name: "missed verdicts", poller: &verdictPoller{err: status.Error(codes.ResourceExhausted, "missed")},
			tenant: "tenant-a", want: http.StatusTooManyRequests},
		{name: "malformed cursor", poller: &verdictPoller{err: status.Error(codes.InvalidArgument, "cursor")},
			tenant: "tenant-a", want: http.StatusBadRequest},
		{name: "feed closed", poller: &verdictPoller{err: status.Error(codes.Unavailable, "closed")},
			tenant: "tenant-a", want: http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := pollVerdicts(mountVerdicts(tt.poller), tt.tenant, tt.query)
			assert.Equal(t, tt.want, w.Code, w.Body.String())
		})
	}
}

func TestVerdictsRouter_RefusesBeforePolling(t *testing.T) {
	poller := &verdictPoller{}
	pollVerdicts(mountVerdicts(poller), "", "")
	pollVerdicts(mountVerdicts(poller), "tenant-a", "wait_ms=-1")
	assert.Empty(t, poller.requests, "a refused caller must not reach the feed")
}
