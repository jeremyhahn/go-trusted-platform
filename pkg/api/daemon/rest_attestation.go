package daemon

import (
	"net/http"

	"github.com/gorilla/mux"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
)

const (
	attestationReadScope   = "attestation:read"
	attestationWriteScope  = "attestation:write"
	attestationDeleteScope = "attestation:delete"
)

// attestationRouteScopes is the scope each attestation route on the daemon
// listener asks, keyed by method and path template. Each route asks the scope
// of the gRPC RPC it calls (pkg/api/grpc/method_permissions.go). The two
// quote-producing routes ask attestation:write, as their QUIC opcodes do: they
// make this node's TPM sign the caller's nonce (docs/attestation/api.md §5).
// A route missing here is refused, so the table is default-deny.
var attestationRouteScopes = map[string]string{
	"GET /api/v1/attestation/manifests":                    attestationReadScope,
	"POST /api/v1/attestation/manifests/build":             attestationWriteScope,
	"POST /api/v1/attestation/manifests/verify":            attestationReadScope,
	"GET /api/v1/attestation/manifests/{id}":               attestationReadScope,
	"DELETE /api/v1/attestation/manifests/{id}":            attestationDeleteScope,
	"POST /api/v1/attestation/quote":                       attestationWriteScope,
	"POST /api/v1/attestation/quote/verify":                attestationReadScope,
	"POST /api/v1/attestation/host":                        attestationWriteScope,
	"POST /api/v1/attestation/vm/{id}":                     attestationWriteScope,
	"POST /api/v1/attestation/container/{id}":              attestationWriteScope,
	"GET /api/v1/attestation/clock":                        attestationReadScope,
	"GET /api/v1/attestation/callers":                      attestationReadScope,
	"GET /api/v1/attestation/reports":                      attestationReadScope,
	"GET /api/v1/attestation/reports/{device_id}":          attestationReadScope,
	"POST /api/v1/attestation/reports/{device_id}/refresh": attestationWriteScope,
	"GET /api/v1/attestation/events":                       attestationReadScope,
}

// ErrAttestationRouteUnclassified is returned for an attestation route the
// scope table does not name.
type ErrAttestationRouteUnclassified struct {
	Route string
}

func (e ErrAttestationRouteUnclassified) Error() string {
	return "attestation route is not classified for authorization: " + e.Route
}

// SetAttestationHandlers mounts the attestation REST routers on the daemon
// listener, the routers the webservice mounts, over the same servicer the
// gRPC, Unix, QUIC and MCP transports call. Every route is scope-gated by
// attestationRouteScopes. The quote and clock routes also admit a machine
// caller through the node's caller-admission policy, exactly as on the
// webservice. reporting and events are optional: without them those routes
// answer that the surface is unavailable.
//
// The device verdict feed (/attestation/verdicts) is not mounted here: it is
// filtered by the webservice session's tenant, and the daemon listener's
// callers present platform tokens, which reach the feed over gRPC, QUIC and
// MCP.
func (s *RESTServer) SetAttestationHandlers(
	server *AttestationServiceServer,
	reporting *restattestation.Reporting,
	events restattestation.EventReader,
	guard *restapi.ScopeGuard,
) {
	if server == nil {
		return
	}
	logger := logging.NewFromSlog(s.logger)
	respWriter := response.NewResponseWriter(logger, nil)
	scoped := attestationScopeGuard(guard, s.writeError)

	operator := s.router.PathPrefix(restBasePath).Subrouter()
	operator.Use(scoped)

	routes := restattestation.NewAttestationServerRouter(logger, server, respWriter)
	routes.RegisterRoutes(operator)
	restattestation.NewCallersRouter(reporting, respWriter).RegisterRoutes(operator)
	restattestation.NewReportsRouter(logger, reporting, respWriter).RegisterRoutes(operator)
	restattestation.NewEventsRouter(logger, events, respWriter).RegisterRoutes(operator)

	// The caller gate decides between a machine caller and an operator, so
	// these routes take the scope guard as the operator path rather than as
	// subrouter middleware.
	var policy restattestation.CallerPolicy
	var clock restattestation.ClockReader
	if reporting != nil {
		policy = reporting.Policy
		clock = reporting.Clock
	}
	gate := restattestation.NewCallerGate(logger, policy, respWriter)
	gated := s.router.PathPrefix(restBasePath).Subrouter()
	routes.RegisterQuoteRoutes(gated, gate, scoped)
	restattestation.NewClockRouter(clock, respWriter).RegisterRoutes(gated, gate, scoped)

	s.logger.Info("Attestation REST routes registered",
		"reporting", reporting != nil, "events", events != nil)
}

// attestationScopeGuard requires the scope attestationRouteScopes names for
// the matched route and refuses a route it does not name.
func attestationScopeGuard(guard *restapi.ScopeGuard, writeError func(http.ResponseWriter, int, error)) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		guarded := make(map[string]http.HandlerFunc, len(attestationRouteScopes))
		for route, scope := range attestationRouteScopes {
			guarded[route] = guard.Require(scope, next.ServeHTTP)
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route := attestationRouteKey(r)
			handler, ok := guarded[route]
			if !ok {
				writeError(w, http.StatusForbidden, ErrAttestationRouteUnclassified{Route: route})
				return
			}
			handler(w, r)
		})
	}
}

// attestationRouteKey is the request's method and matched path template.
func attestationRouteKey(r *http.Request) string {
	template := r.URL.Path
	if route := mux.CurrentRoute(r); route != nil {
		if t, err := route.GetPathTemplate(); err == nil {
			template = t
		}
	}
	return r.Method + " " + template
}
