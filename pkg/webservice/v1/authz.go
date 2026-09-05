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

package v1

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
)

// ErrAuthSeamUnavailable reports that the v1 API could not build the
// inbound authentication seam or the RBAC guard it mounts on protected
// route groups. It is not a request-time error: it is recorded once at
// route-build time, and every protected group then answers 401 instead of
// publishing itself.
type ErrAuthSeamUnavailable struct {
	Reason string
}

// Error implements the error interface.
func (e ErrAuthSeamUnavailable) Error() string {
	return "webservice/v1: inbound authentication seam unavailable: " + e.Reason
}

// gated returns the subrouter that carries the API's protected routes for
// the given role set: an authenticated caller holding ANY of roles.
//
// It is the single place the remaining REST routers are gated, and it
// mounts exactly the seam #159 established for /api/v1/iam — the same
// middleware.Authenticator over the same AuthMiddleware, and the same
// iam.SessionGuard.RequireRoles. Nothing here is a second authentication
// or authorization mechanism; only the place the middleware hangs differs,
// because a router-by-router copy of the mount would let a router added
// later quietly skip it.
//
// The returned value is a mux subrouter carrying NO path matcher of its
// own, so it is transparent to routing: a child still registers its own
// PathPrefix under it, siblings registered on the parent are unaffected,
// and registration order — which the /compute/images-before-/compute
// carve-out depends on — is preserved. gorilla/mux applies a parent
// router's middleware to a match found through a subrouter, which is what
// makes the group a gate rather than decoration.
//
// Groups are memoised per role set, so every admin-gated router shares one
// group and the route table stays flat.
//
// TestRegisterRoutes_EveryRouteDeniesWithoutCredential walks the finished
// table and requires a 401 or 403 from every registered route that is not
// on an explicit, justified public list — so a router mounted on the
// ungated parent by mistake fails the build gate rather than shipping.
func (v1Router *Router) gated(roles ...string) *mux.Router {
	if v1Router.gatedGroups == nil {
		// RegisterRoutes seeds this, but a Router built as a struct literal
		// (package tests do) reaches gated() without it, and a nil map
		// would panic on the memoising write below rather than simply
		// failing to memoise.
		v1Router.gatedGroups = make(map[string]*mux.Router)
	}
	key := strings.Join(roles, ",")
	if group, ok := v1Router.gatedGroups[key]; ok {
		return group
	}
	group := v1Router.router.NewRoute().Subrouter()
	group.Use(v1Router.roleGate(roles)...)
	v1Router.gatedGroups[key] = group
	return group
}

// roleGate returns the middleware chain a protected group mounts:
// authenticate, then require one of roles.
//
// When the inbound authentication seam is unavailable it returns a
// deny-all chain instead. That is the fail-closed branch, and it is
// deliberately "answer 401" rather than "leave the routes unregistered":
// both refuse the request, but an unregistered route is indistinguishable
// from a typo on the caller's side, and an operator debugging a dark API
// needs to be told the difference. The condition is unreachable in the
// daemon — HandlerRegistry.JSONWebTokenHandler aborts startup rather than
// returning nil — so this branch exists for the build-time contract, not
// for a running node.
// operatorChain returns the same authenticate-then-require-roles chain
// gated() mounts, as a single wrapper for a route that must be registered
// on the bare router because another principal is evaluated first (the
// attestation quote routes and their machine-caller gate).
func (v1Router *Router) operatorChain(roles ...string) func(http.Handler) http.Handler {
	chain := v1Router.roleGate(roles)
	return func(next http.Handler) http.Handler {
		h := next
		for i := len(chain) - 1; i >= 0; i-- {
			h = chain[i](h)
		}
		return h
	}
}

func (v1Router *Router) roleGate(roles []string) []mux.MiddlewareFunc {
	authenticate, guard, err := v1Router.authorization()
	if err != nil {
		v1Router.logger.Error(err, "protected REST routes will deny every request")
		return []mux.MiddlewareFunc{v1Router.denyAll(err)}
	}
	return []mux.MiddlewareFunc{
		mux.MiddlewareFunc(authenticate),
		mux.MiddlewareFunc(guard.RequireRoles(roles...)),
	}
}

// authorization resolves the two halves every protected route group and the
// IAM router share: the inbound authentication seam adapted to mux's
// middleware shape, and the session guard that turns the session it
// publishes into role and tenant decisions.
//
// It is one function because there is one seam. The two callers differ only
// in what they do when it is unavailable — a protected group mounts
// denyAll, the IAM router leaves its routes unregistered — and that choice
// belongs to the caller, not here.
func (v1Router *Router) authorization() (
	func(http.Handler) http.Handler, *iammw.SessionGuard, error) {

	authenticate := middleware.Authenticator(v1Router.authMiddleware())
	if authenticate == nil {
		return nil, nil, ErrAuthSeamUnavailable{
			Reason: "no inbound authentication middleware is configured",
		}
	}
	guard, err := iammw.NewSessionGuard(v1Router.logger, v1Router.responseWriter)
	if err != nil {
		return nil, nil, err
	}
	return authenticate, guard, nil
}

// denyAll returns a middleware that refuses every request with 401. It
// stands in for the real guards when they cannot be built, so a group that
// failed to acquire a gate denies rather than opens.
//
// It writes the refusal itself rather than going through the router's
// response.HttpWriter, deliberately. This is the branch where the
// platform's own wiring failed, and the writer can be part of what failed —
// NewSessionGuard refuses to build without one precisely because a guard
// that cannot write a 403 cannot deny. A denial that depends on the
// component that may be missing is not a denial.
func (v1Router *Router) denyAll(cause error) mux.MiddlewareFunc {
	const body = `{"error":"unauthorized","reason":"authentication is not configured"}`
	return func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v1Router.logger.Debugf("webservice/v1: denying %s %s: %v",
				r.Method, r.URL.Path, cause)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			if _, err := w.Write([]byte(body)); err != nil {
				v1Router.logger.Debugf("webservice/v1: denial body not delivered: %v", err)
			}
		})
	}
}
