package daemon

import (
	"context"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

// iamScopeResource is the resource of the scope a request needs: iam:read,
// iam:write or iam:delete.
const iamScopeResource = "iam"

// iamRESTParentPath is the parent the IAM router's /iam base path mounts
// under, so the routes resolve to /api/v1/iam/....
const iamRESTParentPath = "/api/v1"

// iamReadOnlyPosts are the POST routes that only evaluate a request body
// and change nothing, so they need iam:read. They are matched as a suffix
// of the route, which covers the flat and the tenant-scoped form.
var iamReadOnlyPosts = []string{
	"/policies/validate",
	"/policies/test",
	"/permissions/check",
}

// iamWriteDeletes are the DELETE routes that change a membership rather than
// delete an entity: RevokeRole and RemoveGroupMember, both iam:write in the
// gRPC catalog (pkg/api/grpc/method_permissions.go). They are matched as a
// suffix of the route, which covers the flat and the tenant-scoped form.
var iamWriteDeletes = []string{
	"/users/{id}/roles/{role}",
	"/groups/{id}/members/{user}",
}

// iamRESTCallerKey carries the caller ScopeGuard.Authenticate resolved to
// the IAM guards that run after it.
type iamRESTCallerKey struct{}

// SetIAMHandlers mounts /api/v1/iam on the daemon REST plane. The routes are
// the webservice IAM router; the daemon supplies its authorization: the
// platform ScopeGuard authenticates the caller, the caller's iam:* scope
// gates each method, and the tenant rules are the ones the gRPC, QUIC and
// MCP IAM transports apply.
func (s *RESTServer) SetIAMHandlers(logger *logging.Logger, iamClient restiam.IAMClient, pepClient restiam.PEPClient, guard *restapi.ScopeGuard, systemTenantID string) error {
	switch {
	case logger == nil:
		return ErrIAMRESTUnavailable{Reason: "no logger"}
	case iamClient == nil:
		return ErrIAMRESTUnavailable{Reason: "no IAM client"}
	case pepClient == nil:
		return ErrIAMRESTUnavailable{Reason: "no IAM PEP client"}
	case guard == nil:
		return ErrIAMRESTUnavailable{Reason: "no REST scope guard"}
	}
	respWriter := response.NewResponseWriter(logger, nil)
	authz := iamRESTAuthorization{guard: guard, respWriter: respWriter, systemTenantID: systemTenantID}
	router, err := restiam.NewIAMRouter(logger, iamClient, pepClient, respWriter, restiam.Authorization{
		Authenticate:        authz.authenticate,
		RequireAdmin:        authz.requireScope,
		RequireSystemTenant: authz.requireSystemTenant,
		RequireOwnTenant:    authz.requireOwnTenant,
	})
	if err != nil {
		return ErrIAMRESTUnavailable{Reason: err.Error()}
	}
	// The IAM router's base path is relative to the /api/v1 parent.
	router.RegisterRoutes(s.router.PathPrefix(iamRESTParentPath).Subrouter())
	s.logger.Info("IAM REST routes registered")
	return nil
}

// iamRESTAuthorization is the daemon's authorization for the IAM router.
type iamRESTAuthorization struct {
	guard          *restapi.ScopeGuard
	respWriter     response.HttpWriter
	systemTenantID string
}

// authenticate resolves the caller and carries it to the guards after it.
func (a iamRESTAuthorization) authenticate(next http.Handler) http.Handler {
	return a.guard.Authenticate(func(w http.ResponseWriter, r *http.Request, caller *platformtoken.AuthorizedContext) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), iamRESTCallerKey{}, caller)))
	})
}

// requireScope serves next only to a caller holding the iam:* scope the
// request's method needs.
func (a iamRESTAuthorization) requireScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, ok := a.caller(w, r)
		if !ok {
			return
		}
		action, err := iamScopeAction(r.Method, restRouteTemplate(r))
		if err != nil {
			a.respWriter.Error403(w, r, err, nil)
			return
		}
		scope := iamScopeResource + ":" + action
		if err := caller.RequireScope(scope); err != nil {
			a.respWriter.Error403(w, r, restapi.ErrRouteForbidden{Scope: scope, Reason: err.Error()}, nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireSystemTenant serves next only to a caller of the system tenant.
func (a iamRESTAuthorization) requireSystemTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, ok := a.caller(w, r)
		if !ok {
			return
		}
		method := r.Method + " " + restRouteTemplate(r)
		if err := systemCallerDecision(a.systemTenantID, caller.TenantID, method); err != nil {
			a.respWriter.Error403(w, r, err, nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireOwnTenant serves next only when the request names the caller's
// own tenant.
func (a iamRESTAuthorization) requireOwnTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, ok := a.caller(w, r)
		if !ok {
			return
		}
		if err := iamTenantDecision(caller.TenantID, restiam.RequestedTenant(r)); err != nil {
			a.respWriter.Error403(w, r, err, nil)
			return
		}
		next.ServeHTTP(w, withVerifiedTenant(r, caller.TenantID))
	})
}

// withVerifiedTenant returns r with the {tenant} route variable set to the
// caller's verified tenant, which the IAM handlers read. Flat routes name the
// tenant only in the query, which the handlers deliberately ignore, so the
// tenant the ownership check admitted is carried to them here.
func withVerifiedTenant(r *http.Request, tenantID string) *http.Request {
	routeVars := mux.Vars(r)
	vars := make(map[string]string, len(routeVars)+1)
	for name, value := range routeVars {
		vars[name] = value
	}
	vars["tenant"] = tenantID
	return mux.SetURLVars(r, vars)
}

// caller returns the caller authenticate resolved. A request that reached a
// guard without one is refused with 403.
func (a iamRESTAuthorization) caller(w http.ResponseWriter, r *http.Request) (*platformtoken.AuthorizedContext, bool) {
	caller, ok := r.Context().Value(iamRESTCallerKey{}).(*platformtoken.AuthorizedContext)
	if !ok || caller == nil {
		a.respWriter.Error403(w, r, restapi.ErrRouteForbidden{Reason: "the request carries no authenticated caller"}, nil)
		return nil, false
	}
	return caller, true
}

// iamScopeAction returns the IAM action a request performs: read, write or
// delete. The three read-only POSTs need read and the membership DELETEs need
// write. An unknown method is refused.
func iamScopeAction(method, route string) (string, error) {
	if method == http.MethodDelete {
		for _, suffix := range iamWriteDeletes {
			if strings.HasSuffix(route, suffix) {
				return "write", nil
			}
		}
	}
	return restScopeAction(iamScopeResource, iamReadOnlyPosts, method, route)
}
