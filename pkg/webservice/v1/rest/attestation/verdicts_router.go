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
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// verdictHeartbeatInterval is how often an idle verdict stream sends an SSE
// comment, so a proxy or load balancer does not close the connection.
const verdictHeartbeatInterval = 15 * time.Second

// VerdictsRouter serves the device verdict stream as Server-Sent Events:
//
//	GET /api/v1/attestation/verdicts/stream
//
// Each recorded verdict is one `verdict` event whose data is the protojson
// DeviceVerdictEvent gRPC StreamDeviceVerdicts sends. The stream ends when the
// client disconnects, the daemon shuts down, or the subscriber falls behind;
// the last two are announced with an `error` event so the client knows it must
// follow again.
//
// The router holds no audience rules: the stream service decides who sees which
// tenant's verdicts for every transport. The router only tells it who is
// calling. Mount on the admin gate.
type VerdictsRouter struct {
	opener     verdict.StreamOpener
	respWriter response.HttpWriter
	heartbeat  time.Duration
}

// NewVerdictsRouter builds the router. A nil opener registers a route that
// answers 503, so an operator can tell "not served here" from a typo.
func NewVerdictsRouter(opener verdict.StreamOpener, respWriter response.HttpWriter) *VerdictsRouter {
	return &VerdictsRouter{opener: opener, respWriter: respWriter, heartbeat: verdictHeartbeatInterval}
}

// RegisterRoutes mounts the route.
func (r *VerdictsRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix("/attestation").Subrouter()
	sr.HandleFunc("/verdicts/stream", r.stream).Methods(http.MethodGet)
}

// ErrVerdictStreamNotConfigured reports a node with no verdict stream.
type ErrVerdictStreamNotConfigured struct{}

func (ErrVerdictStreamNotConfigured) Error() string {
	return "attestation: the device verdict stream is not available on this node"
}

// ErrVerdictStreamingUnsupported reports a response writer that cannot flush,
// which an event stream needs.
type ErrVerdictStreamingUnsupported struct{}

func (ErrVerdictStreamingUnsupported) Error() string {
	return "attestation: the response writer does not support streaming"
}

// verdictPrincipalOf reports who is calling: the tenant of the IAM session the
// authentication chain published, and whether a client certificate came with
// the request. A request that is neither carries no credential, and REST has no
// Unix peer-credential caller.
func verdictPrincipalOf(req *http.Request) verdict.StreamPrincipal {
	principal := verdict.StreamPrincipal{
		HasCertificate: req.TLS != nil && len(req.TLS.PeerCertificates) > 0,
	}
	if session, ok := iam.GetSessionFromContext(req.Context()); ok && session != nil {
		principal.TenantID = session.TenantID()
	}
	return principal
}

func (r *VerdictsRouter) stream(w http.ResponseWriter, req *http.Request) {
	if r.opener == nil {
		r.refuse(w, req, http.StatusServiceUnavailable, ErrVerdictStreamNotConfigured{})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		r.refuse(w, req, http.StatusInternalServerError, ErrVerdictStreamingUnsupported{})
		return
	}
	subscription, err := r.opener.OpenVerdictStream(verdictPrincipalOf(req))
	if err != nil {
		r.refuse(w, req, verdictOpenStatus(err), err)
		return
	}
	defer subscription.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// The comment tells the client its subscription is live before any verdict.
	fmt.Fprint(w, ": subscribed\n\n")
	flusher.Flush()

	err = subscription.Serve(req.Context(), func(recorded verdict.RecordedDeviceVerdict) error {
		data, err := protojson.Marshal(verdict.EventOf(recorded))
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "id: %s\nevent: verdict\ndata: %s\n\n", recorded.EventID, data); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}, verdict.StreamHeartbeat{Every: r.heartbeat, Beat: func() error {
		if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}})
	if err == nil || req.Context().Err() != nil {
		return
	}
	var closed verdict.ErrStreamClosed
	var behind verdict.ErrSubscriberBehind
	if errors.As(err, &closed) || errors.As(err, &behind) {
		fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
		flusher.Flush()
	}
}

// refuse answers before the event stream starts, as ordinary JSON.
func (r *VerdictsRouter) refuse(w http.ResponseWriter, req *http.Request, code int, err error) {
	if code == http.StatusForbidden {
		r.respWriter.Error403(w, req, err, nil)
		return
	}
	r.respWriter.Write(w, req, code, response.WebServiceResponse{Code: code, Error: err.Error()})
}

// verdictOpenStatus maps the reason a subscription was not opened to its
// HTTP status.
func verdictOpenStatus(err error) int {
	var forbidden verdict.ErrStreamForbidden
	if errors.As(err, &forbidden) {
		return http.StatusForbidden
	}
	var unavailable verdict.ErrStreamUnavailable
	var closed verdict.ErrStreamClosed
	if errors.As(err, &unavailable) || errors.As(err, &closed) {
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}
