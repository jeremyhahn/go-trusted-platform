package daemon

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// restMethodActions maps an HTTP method to the action it performs on a
// daemon REST resource, matching the gRPC method permissions. A method that
// is not listed is refused, never defaulted.
var restMethodActions = map[string]string{
	http.MethodGet:    "read",
	http.MethodPost:   "write",
	http.MethodPut:    "write",
	http.MethodPatch:  "write",
	http.MethodDelete: "delete",
}

// restScopeAction returns the action a request on resource performs: read,
// write or delete. A POST whose route template ends in one of readOnlyPosts
// only evaluates its body, so it is a read, as its gRPC method is.
func restScopeAction(resource string, readOnlyPosts []string, method, route string) (string, error) {
	action, ok := restMethodActions[method]
	if !ok {
		return "", restapi.ErrRouteForbidden{Scope: resource + ":*", Reason: "method " + method + " is not served"}
	}
	if method == http.MethodPost {
		for _, suffix := range readOnlyPosts {
			if strings.HasSuffix(route, suffix) {
				return "read", nil
			}
		}
	}
	return action, nil
}

// restRouteTemplate is the path template of the matched route, or the
// request path when no route matched.
func restRouteTemplate(r *http.Request) string {
	if route := mux.CurrentRoute(r); route != nil {
		if template, err := route.GetPathTemplate(); err == nil {
			return template
		}
	}
	return r.URL.Path
}

// sdnScopeResource is the scope resource of every SDN route: sdn:read,
// sdn:write or sdn:delete. No SDN POST is read-only.
const sdnScopeResource = "sdn"

// sdnPortAuthRoute is RevokePortAuth's route. Its DELETE revokes a port's
// authorization, which the gRPC catalog gives sdn:write, not sdn:delete.
const sdnPortAuthRoute = "/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}/auth"

// sdnRouteScope is the scope an SDN request needs.
func sdnRouteScope(method, route string) (string, error) {
	if method == http.MethodDelete && route == sdnPortAuthRoute {
		return sdnScopeResource + ":write", nil
	}
	action, err := restScopeAction(sdnScopeResource, nil, method, route)
	if err != nil {
		return "", err
	}
	return sdnScopeResource + ":" + action, nil
}

// restScopeAuthorization authenticates a daemon REST request through the
// REST scope guard and requires the scope routeScope gives its method and
// route template.
type restScopeAuthorization struct {
	guard      *restapi.ScopeGuard
	respWriter response.HttpWriter
	routeScope func(method, route string) (string, error)
}

// authorize answers 401 for a missing or invalid credential and 403 for a
// caller without the route's scope.
func (a restScopeAuthorization) authorize(next http.Handler) http.Handler {
	return a.guard.Authenticate(func(w http.ResponseWriter, r *http.Request, caller *platformtoken.AuthorizedContext) {
		scope, err := a.routeScope(r.Method, restRouteTemplate(r))
		if err != nil {
			a.respWriter.Error403(w, r, err, nil)
			return
		}
		if err := caller.RequireScope(scope); err != nil {
			a.respWriter.Error403(w, r, restapi.ErrRouteForbidden{Scope: scope, Reason: err.Error()}, nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}
