package daemon

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
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

// catalogRouteRPCs maps each PIV, LUKS and FIDO2 route on the daemon REST
// listener, as "METHOD route-template", to the gRPC method it serves. The
// route needs the scope the gRPC catalog gives that method: several of these
// POSTs read, delete or use a key, so the HTTP method cannot name the action.
var catalogRouteRPCs = map[string]string{
	"GET /api/v1/piv/devices":                 "/platform.v1.PIVService/ListDevices",
	"GET /api/v1/piv/devices/{device}/slots":  "/platform.v1.PIVService/ListSlots",
	"GET /api/v1/piv/slots/{slot}":            "/platform.v1.PIVService/SlotInfo",
	"POST /api/v1/piv/slots/{slot}/attest":    "/platform.v1.PIVService/Attest",
	"POST /api/v1/piv/slots/{slot}/generate":  "/platform.v1.PIVService/Generate",
	"POST /api/v1/piv/slots/{slot}/import":    "/platform.v1.PIVService/Import",
	"POST /api/v1/piv/slots/{slot}/sign":      "/platform.v1.PIVService/Sign",
	"POST /api/v1/piv/devices/{device}/reset": "/platform.v1.PIVService/Reset",

	"GET /api/v1/luks/status":             "/platform.v1.LUKSService/Status",
	"GET /api/v1/luks/slots":              "/platform.v1.LUKSService/ListSlots",
	"GET /api/v1/luks/info":               "/platform.v1.LUKSService/Info",
	"POST /api/v1/luks/keys/test-unlock":  "/platform.v1.LUKSService/TestUnlock",
	"POST /api/v1/luks/enroll/passphrase": "/platform.v1.LUKSService/EnrollPassphrase",
	"POST /api/v1/luks/enroll/fido2":      "/platform.v1.LUKSService/EnrollFIDO2",
	"POST /api/v1/luks/enroll/tpm":        "/platform.v1.LUKSService/EnrollTPM",
	"POST /api/v1/luks/enroll/recovery":   "/platform.v1.LUKSService/EnrollRecovery",
	"POST /api/v1/luks/passphrase/change": "/platform.v1.LUKSService/ChangePassphrase",
	"POST /api/v1/luks/keys/remove":       "/platform.v1.LUKSService/RemoveKey",

	"GET /api/v1/fido2/devices":          "/platform.v1.FIDO2Service/ListDevices",
	"GET /api/v1/fido2/devices/wait":     "/platform.v1.FIDO2Service/WaitDevice",
	"GET /api/v1/fido2/devices/{device}": "/platform.v1.FIDO2Service/Info",
	"POST /api/v1/fido2/register":        "/platform.v1.FIDO2Service/Register",
	"POST /api/v1/fido2/authenticate":    "/platform.v1.FIDO2Service/Authenticate",
}

// catalogRouteScope returns the scope the gRPC catalog gives the method a
// route serves. A route missing from catalogRouteRPCs, or a method the
// catalog gives no scope, fails closed.
func catalogRouteScope(method, route string) (string, error) {
	rpc, ok := catalogRouteRPCs[method+" "+route]
	if !ok {
		return "", ErrRESTRouteUnscoped{Method: method, Route: route, Reason: "the route has no gRPC method"}
	}
	scope := grpcapi.ScopeForMethod(rpc)
	if scope == "" {
		return "", ErrRESTRouteUnscoped{Method: method, Route: route, Reason: "the gRPC catalog gives " + rpc + " no scope"}
	}
	return scope, nil
}

// catalogGuardedAPI returns a restBasePath subrouter whose routes each run
// behind guard and need the scope catalogRouteScope gives them.
func (s *RESTServer) catalogGuardedAPI(guard *restapi.ScopeGuard) *mux.Router {
	authz := restScopeAuthorization{
		guard:      guard,
		respWriter: response.NewResponseWriter(logging.NewFromSlog(s.logger), nil),
		routeScope: catalogRouteScope,
	}
	api := s.router.PathPrefix(restBasePath).Subrouter()
	api.Use(authz.authorize)
	return api
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
