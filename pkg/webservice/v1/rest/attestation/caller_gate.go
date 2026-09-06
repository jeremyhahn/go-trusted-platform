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

package attestation

import (
	"context"
	"crypto/x509"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// CallerPolicy is the node-side admission policy as the REST layer uses it.
// *calleradmission.Policy satisfies it.
type CallerPolicy interface {
	Evaluate(ctx context.Context, peer *calleradmission.Peer) calleradmission.Decision
	Describe() calleradmission.Description
	Anchors() []*x509.Certificate
}

// Reporting is what the attestation reporting service exposes to the REST
// layer. Every field is optional: a node that only answers quotes has a
// Policy and nothing else; a control plane running the collector has all
// three.
type Reporting struct {
	// Reports is the read-only report cache. A handler holding it cannot
	// reach a device (pkg/attestation/reporting).
	Reports reporting.Viewer
	// Refresher enqueues out-of-cycle collection with the collector.
	Refresher reporting.Refresher
	// Policy admits machine callers to the quote-producing routes.
	Policy CallerPolicy
	// Clock reads this node's own clock trust state for the collector.
	// Present on every node that runs a time service, including workers
	// that hold no cache.
	Clock ClockReader
}

// callerContextKey carries the admitted machine identity.
type callerContextKey struct{}

// AdmittedCaller returns the machine identity the caller gate admitted for
// this request, if any.
func AdmittedCaller(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(callerContextKey{}).(string)
	return id, ok && id != ""
}

// CallerGate wraps a quote-producing handler with the machine-caller path.
//
// Order of evaluation, and why:
//
//  1. No client certificate presented: the request is an operator's, and
//     the operator chain (JWT + admin role) decides. Nothing about the
//     machine policy applies.
//  2. A client certificate presented: the policy decides, and its decision
//     is final for this request. A refused machine caller is NOT handed to
//     the operator chain, because a refusal is an audited security decision
//     and a second chance would let a peer that failed admission try the
//     credential path instead.
//
// Every machine decision is audited by the policy itself.
type CallerGate struct {
	policy     CallerPolicy
	respWriter response.HttpWriter
	logger     *logging.Logger
}

// NewCallerGate builds the gate. A nil policy yields a gate that hands
// every request to the operator chain, which is the pre-#226 behaviour and
// is safe: it admits no machine caller.
func NewCallerGate(logger *logging.Logger, policy CallerPolicy, respWriter response.HttpWriter) *CallerGate {
	return &CallerGate{policy: policy, respWriter: respWriter, logger: logger}
}

// Wrap returns the gated handler. operator is the operator authentication
// chain applied around next when no machine identity is presented.
func (g *CallerGate) Wrap(next http.Handler, operator func(http.Handler) http.Handler) http.Handler {
	operatorPath := next
	if operator != nil {
		operatorPath = operator(next)
	}
	if g == nil || g.policy == nil {
		return operatorPath
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, presented := calleradmission.PeerFromTLS(r.TLS, r.RemoteAddr)
		if !presented {
			operatorPath.ServeHTTP(w, r)
			return
		}
		d := g.policy.Evaluate(r.Context(), peer)
		if !d.Admitted {
			g.logger.Warn("attestation: machine caller refused",
				"identity", d.Identity, "reason", string(d.Reason), "strategy", string(d.Strategy),
				"remote", d.RemoteAddr, "detail", d.Detail)
			err := ErrCallerRefused{Identity: d.Identity, Reason: d.Reason}
			if d.Reason == calleradmission.ReasonUntrustedIssuer || d.Reason == calleradmission.ReasonNoIdentity {
				g.respWriter.Error401(w, r, err)
				return
			}
			g.respWriter.Error403(w, r, err, nil)
			return
		}
		ctx := context.WithValue(r.Context(), callerContextKey{}, d.Identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ErrCallerRefused is the machine caller's refusal as the wire sees it. It
// names the reason class, never the policy's identity list.
type ErrCallerRefused struct {
	Identity string
	Reason   calleradmission.Reason
}

func (e ErrCallerRefused) Error() string {
	if e.Identity == "" {
		return "attestation: machine caller refused: " + string(e.Reason)
	}
	return "attestation: machine caller " + e.Identity + " refused: " + string(e.Reason)
}

// CallersRouter describes the node's effective caller-admission policy, so
// an operator sees what is ENFORCED rather than inferring it from config:
//
//	GET /api/v1/attestation/callers
//
// Mount on the admin gate.
type CallersRouter struct {
	reporting  *Reporting
	respWriter response.HttpWriter
}

// NewCallersRouter builds the router. A nil Reporting (or nil Policy)
// describes a policy that admits nobody, which is the truth: with no policy
// the quote routes take only the operator chain.
func NewCallersRouter(rep *Reporting, respWriter response.HttpWriter) *CallersRouter {
	return &CallersRouter{reporting: rep, respWriter: respWriter}
}

// RegisterRoutes mounts the route.
func (r *CallersRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix("/attestation").Subrouter()
	sr.HandleFunc("/callers", r.describeCallers).Methods(http.MethodGet)
}

func (r *CallersRouter) describeCallers(w http.ResponseWriter, req *http.Request) {
	if r.reporting == nil || r.reporting.Policy == nil {
		r.respWriter.Success200(w, req, calleradmission.Description{AdmitsNobody: true})
		return
	}
	r.respWriter.Success200(w, req, r.reporting.Policy.Describe())
}
