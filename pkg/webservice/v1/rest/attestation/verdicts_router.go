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

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict/feed"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// VerdictPoller answers one long-poll of the device verdict feed for an
// audience the transport decided. The daemon's AttestationServiceServer
// implements it, so REST shares cursors, waits and errors with gRPC.
type VerdictPoller interface {
	PollDeviceVerdictsFor(ctx context.Context, audience feed.Audience, req *platformv1.PollDeviceVerdictsRequest) (*platformv1.PollDeviceVerdictsResponse, error)
}

// VerdictsRouter serves the device verdict feed (#709) as a long-poll:
//
//	GET /api/v1/attestation/verdicts?cursor=&wait_ms= - verdicts after cursor
//
// HTTP carries no server stream, so a client follows the feed by passing each
// reply's cursor to its next poll; the SDK's StreamDeviceVerdicts does that.
type VerdictsRouter struct {
	poller     VerdictPoller
	respWriter response.HttpWriter
}

// NewVerdictsRouter builds the router. A nil poller registers a route that
// answers 503, so an operator can tell "not configured here" from a typo.
func NewVerdictsRouter(poller VerdictPoller, respWriter response.HttpWriter) *VerdictsRouter {
	return &VerdictsRouter{poller: poller, respWriter: respWriter}
}

// RegisterRoutes mounts the route. Mount on the admin gate: a verdict is a
// security judgement about a machine.
func (r *VerdictsRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix("/attestation").Subrouter()
	sr.HandleFunc("/verdicts", r.pollVerdicts).Methods(http.MethodGet)
}

// pollVerdicts answers one poll for the caller's verified session: its tenant
// sees its own devices' verdicts, the platform tenant sees every tenant's, and
// a session naming no tenant is refused before the feed is reached.
func (r *VerdictsRouter) pollVerdicts(w http.ResponseWriter, req *http.Request) {
	if r.poller == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "attestation verdicts"})
		return
	}
	tenantID := sessionTenant(req)
	if tenantID == "" {
		r.respWriter.Error403(w, req, ErrVerdictsForbidden{}, nil)
		return
	}
	waitMs, err := protorest.QueryUint32(req, "wait_ms")
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	page, err := r.poller.PollDeviceVerdictsFor(req.Context(), feed.Tenant(tenantID),
		&platformv1.PollDeviceVerdictsRequest{Cursor: req.URL.Query().Get("cursor"), WaitMs: waitMs})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, page)
}

// sessionTenant is the tenant of the verified session the auth middleware
// published, or "" when there is none.
func sessionTenant(req *http.Request) string {
	if session, ok := iammw.GetSessionFromContext(req.Context()); ok && session != nil {
		return session.TenantID()
	}
	return ""
}

// ErrVerdictsForbidden reports a caller whose session names no tenant, so no
// verdict audience can be decided for it.
type ErrVerdictsForbidden struct{}

func (ErrVerdictsForbidden) Error() string {
	return "attestation: device verdicts denied: the session names no tenant"
}
