package daemon

import (
	"context"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

// iamScopePrefix prefixes the action a request needs: iam:read, iam:write
// or iam:delete.
const iamScopePrefix = "iam:"

// iamRESTParentPath is the parent the IAM router's /iam base path mounts
// under, so the routes resolve to /api/v1/iam/....
const iamRESTParentPath = "/api/v1"

// iamMethodActions maps an HTTP method to the IAM action it performs. A
// method missing from the map is refused, never defaulted.
var iamMethodActions = map[string]string{
	http.MethodGet:    "read",
	http.MethodPost:   "write",
	http.MethodPut:    "write",
	http.MethodPatch:  "write",
	http.MethodDelete: "delete",
}

// iamReadOnlyPosts are the POST routes that only evaluate a request body
// and change nothing, so they need iam:read. They are matched as a suffix
// of the route, which covers the flat and the tenant-scoped form.
var iamReadOnlyPosts = []string{
	"/policies/validate",
	"/policies/test",
	"/permissions/check",
}

// iamMembershipDeletes are the DELETE routes that remove a membership
// rather than an IAM object: RevokeUserRole and RemoveGroupMember, on the
// tenant path and its flat alias. The shared RPC catalog
// (pkg/api/grpc/method_permissions.go) grants RevokeRole and
// RemoveGroupMember to iam:write, so REST asks for the same scope.
var iamMembershipDeletes = []string{
	"/users/{id}/roles/{role}",
	"/groups/{id}/members/{user}",
}

// iamRouteAction is a route suffix whose scope action differs from the
// one its method maps to in iamMethodActions.
// iamRouteKey names one IAM route by its method and path template.
type iamRouteKey struct {
	method   string
	template string
}

// iamOperationsAwaitingSDK are the IAM routes, relative to a tenant scope,
// whose SDK operation the pinned go-quicbaas SDK (v0.12.0-alpha) cannot
// dispatch on its embedded transport: transport/embedded/iam_dispatch.go
// carries no handler for them, so mounted they answer 500 with
// UnknownMethodError. The daemon leaves them out until the SDK v0.16 adoption
// (#906) brings the operations. The last two are dispatched but cannot be
// served correctly, so they are left out for the same adoption.
var iamOperationsAwaitingSDK = []iamRouteKey{
	{http.MethodPost, "/users/{id}/roles/{role}"},      // quicbaas.IAM.User/AssignRole
	{http.MethodDelete, "/users/{id}/roles/{role}"},    // quicbaas.IAM.User/RevokeRole
	{http.MethodPost, "/groups/{id}/members/{user}"},   // quicbaas.IAM.Group/AddMember
	{http.MethodDelete, "/groups/{id}/members/{user}"}, // quicbaas.IAM.Group/RemoveMember
	{http.MethodPost, "/policies/validate"},            // quicbaas.IAM.Policy/Validate
	{http.MethodPost, "/policies/test"},                // quicbaas.IAM.Policy/Test
	{http.MethodPut, "/policies/{id}"},                 // quicbaas.IAM.Policy/Update
	{http.MethodPut, "/apps/{id}"},                     // quicbaas.IAM.App/Update
	{http.MethodPost, "/apps/{id}/rotate"},             // quicbaas.IAM.App/RotateSecret
	// quicbaas.IAM.App/Register: the embedded handleIAMAppRegister answers
	// through sdkAppFromInternal, which drops ClientSecret, so registration
	// would succeed without the only copy of the application's secret.
	{http.MethodPost, "/apps"},
	// quicbaas.IAM.PEP/Check: the embedded handleIAMPEPCheck always answers
	// ServiceNotConfiguredError("IAM.PEP"), never a verdict.
	{http.MethodPost, "/permissions/check"},
}

// iamRoutesAwaitingSDK is iamOperationsAwaitingSDK under both route forms:
// the tenant-scoped /iam/tenants/{tenant}/... and the flat /iam/....
var iamRoutesAwaitingSDK = iamRouteKeysUnderBothForms(iamOperationsAwaitingSDK)

func iamRouteKeysUnderBothForms(operations []iamRouteKey) map[iamRouteKey]struct{} {
	const iamBase = iamRESTParentPath + "/iam"
	out := make(map[iamRouteKey]struct{}, 2*len(operations))
	for _, op := range operations {
		for _, scope := range []string{iamBase + "/tenants/{tenant}", iamBase} {
			out[iamRouteKey{method: op.method, template: scope + op.template}] = struct{}{}
		}
	}
	return out
}

type iamRouteAction struct {
	suffix string
	action string
}

// iamRouteActionExceptions lists, per method, the routes that need a
// scope action other than the method's own.
var iamRouteActionExceptions = map[string][]iamRouteAction{
	http.MethodPost:   iamRouteActions(iamReadOnlyPosts, "read"),
	http.MethodDelete: iamRouteActions(iamMembershipDeletes, "write"),
}

func iamRouteActions(suffixes []string, action string) []iamRouteAction {
	out := make([]iamRouteAction, 0, len(suffixes))
	for _, suffix := range suffixes {
		out = append(out, iamRouteAction{suffix: suffix, action: action})
	}
	return out
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
	router, err := restiam.NewIAMRouter(logger, iamTenantApps{IAMClient: iamClient}, pepClient, respWriter, restiam.Authorization{
		Authenticate:        authz.authenticate,
		RequireAdmin:        authz.requireScope,
		RequireSystemTenant: authz.requireSystemTenant,
		RequireOwnTenant:    authz.requireOwnTenant,
	})
	if err != nil {
		return ErrIAMRESTUnavailable{Reason: err.Error()}
	}
	if err := s.mountIAMRoutes(router); err != nil {
		return ErrIAMRESTUnavailable{Reason: err.Error()}
	}
	s.logger.Info("IAM REST routes registered")
	return nil
}

// mountIAMRoutes mounts on the daemon router every IAM route except those in
// iamRoutesAwaitingSDK. The IAM router registers its whole table, with its
// authentication and admin guards, on a router of its own; each served route
// is then mounted on the daemon router by its method and path template and
// delegates to that router, so the guards run exactly as before.
//
// A served route matches its method with a matcher func rather than mux's
// Methods matcher: a Methods mismatch answers 405, and a left-out route that
// shares its path with a served one (PUT /policies/{id} beside GET) must answer
// 404 like any unknown path.
func (s *RESTServer) mountIAMRoutes(iamRouter *restiam.IAMRouter) error {
	routes := mux.NewRouter()
	// The IAM router's base path is relative to the /api/v1 parent.
	iamRouter.RegisterRoutes(routes.PathPrefix(iamRESTParentPath).Subrouter())
	return routes.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if route.GetHandler() == nil {
			// A path-prefix route that only holds a subrouter.
			return nil
		}
		template, err := route.GetPathTemplate()
		if err != nil {
			return err
		}
		methods, err := route.GetMethods()
		if err != nil {
			return err
		}
		for _, method := range methods {
			if _, awaiting := iamRoutesAwaitingSDK[iamRouteKey{method: method, template: template}]; awaiting {
				continue
			}
			s.router.Handle(template, routes).MatcherFunc(iamMethodMatcher(method))
		}
		return nil
	})
}

// iamMethodMatcher matches requests whose method is method.
func iamMethodMatcher(method string) mux.MatcherFunc {
	return func(r *http.Request, _ *mux.RouteMatch) bool {
		return r.Method == method
	}
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
		action, err := iamScopeAction(r.Method, iamRouteTemplate(r))
		if err != nil {
			a.respWriter.Error403(w, r, err, nil)
			return
		}
		scope := iamScopePrefix + action
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
		method := r.Method + " " + iamRouteTemplate(r)
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
		requested := restiam.RequestedTenant(r)
		if err := iamTenantDecision(caller.TenantID, requested); err != nil {
			a.respWriter.Error403(w, r, err, nil)
			return
		}
		// The daemon's flat routes carry neither a {tenant} path variable
		// nor a webservice session, so hand the handlers the tenant this
		// guard has just authorized.
		next.ServeHTTP(w, r.WithContext(restiam.WithAuthorizedTenant(r.Context(), requested)))
	})
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
// delete. The three read-only POSTs need read. An unknown method is refused.
func iamScopeAction(method, route string) (string, error) {
	action, ok := iamMethodActions[method]
	if !ok {
		return "", restapi.ErrRouteForbidden{Scope: iamScopePrefix + "*", Reason: "method " + method + " is not served"}
	}
	exceptions, ok := iamRouteActionExceptions[method]
	if !ok {
		return action, nil
	}
	for _, exception := range exceptions {
		if strings.HasSuffix(route, exception.suffix) {
			return exception.action, nil
		}
	}
	return action, nil
}

// iamRouteTemplate is the path template of the matched route, or the
// request path when no route matched.
func iamRouteTemplate(r *http.Request) string {
	if route := mux.CurrentRoute(r); route != nil {
		if template, err := route.GetPathTemplate(); err == nil {
			return template
		}
	}
	return r.URL.Path
}

// iamTenantApps keeps the application instance routes inside the URL
// tenant. The pinned SDK looks an application's client ID up across every
// tenant for Get, Update, Delete and RotateSecret, so the URL tenant check
// alone would let a caller reach another tenant's application by its
// client ID. Each call first confirms, through the tenant-scoped List, that
// the client ID belongs to the tenant; a foreign client ID gets the same
// not-found as a missing one, and nothing is changed.
type iamTenantApps struct {
	restiam.IAMClient
}

func (c iamTenantApps) GetApp(ctx context.Context, tenantID, clientID string) (*sdkiam.Application, error) {
	if err := c.requireTenantApp(ctx, tenantID, clientID); err != nil {
		return nil, err
	}
	return c.IAMClient.GetApp(ctx, tenantID, clientID)
}

func (c iamTenantApps) UpdateApp(ctx context.Context, tenantID, clientID string, req *sdkiam.UpdateAppRequest) (*sdkiam.Application, error) {
	if err := c.requireTenantApp(ctx, tenantID, clientID); err != nil {
		return nil, err
	}
	return c.IAMClient.UpdateApp(ctx, tenantID, clientID, req)
}

func (c iamTenantApps) DeleteApp(ctx context.Context, tenantID, clientID string) error {
	if err := c.requireTenantApp(ctx, tenantID, clientID); err != nil {
		return err
	}
	return c.IAMClient.DeleteApp(ctx, tenantID, clientID)
}

func (c iamTenantApps) RotateAppSecret(ctx context.Context, tenantID, clientID string) (*restiam.RotateSecretResponse, error) {
	if err := c.requireTenantApp(ctx, tenantID, clientID); err != nil {
		return nil, err
	}
	return c.IAMClient.RotateAppSecret(ctx, tenantID, clientID)
}

// requireTenantApp returns restiam.ErrAppNotFound unless the tenant's own
// application list holds the client ID.
func (c iamTenantApps) requireTenantApp(ctx context.Context, tenantID, clientID string) error {
	apps, err := c.ListApps(ctx, tenantID, 0, 0)
	if err != nil {
		return err
	}
	for i := range apps.Apps {
		if apps.Apps[i].ClientID == clientID {
			return nil
		}
	}
	return restiam.ErrAppNotFound{TenantID: tenantID, AppID: clientID}
}
