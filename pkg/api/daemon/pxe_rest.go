package daemon

import (
	"context"
	"net/http"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restpxe "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/pxe"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SetPXERouterHandlers mounts the PXE operator routes (status, start, stop,
// devices and their lifecycle) at /api/v1/pxe on the daemon REST listener.
// server is the PXEServiceServer gRPC, QUIC, MCP and Unix serve, so a
// platformd without a PXE backend answers ErrPXENotConfigured on REST too.
// The PXE router checks the pxe:* scope the gRPC catalog gives each route's
// rpc through guard. The credential-less install webhook and the per-MAC
// gateway routes are the webservice's and are not mounted here.
func (s *RESTServer) SetPXERouterHandlers(logger *logging.Logger, server platformv1.PXEServiceServer, guard *restapi.ScopeGuard) error {
	switch {
	case logger == nil:
		return ErrPXERESTUnavailable{Reason: "no logger"}
	case server == nil:
		return ErrPXERESTUnavailable{Reason: "no PXE service"}
	case guard == nil:
		// Without an authorizer the PXE router mounts every route unguarded.
		return ErrPXERESTUnavailable{Reason: "no REST scope guard"}
	}
	writer := response.NewResponseWriter(logger, nil)
	pxeRouter := restpxe.NewPXERouter(logger, server, writer, false)
	// The scope check answers a bound caller's refusal itself, so it takes
	// the writer as well as the guard.
	pxeRouter.SetScopeAuthorizer(restScopeAuthorizer{guard: guard, respWriter: writer})
	// The PXE device store is platform-wide, so only the system tenant may
	// reach it (#1896 Codex r10). The guard binds the bearer's tenant to the
	// request, and PXEService's authorizeSystemCaller refuses any other.
	pxeRouter.SetSystemTenantGuard(pxeRESTCallerBinding(guard))
	// The PXE router's paths are relative to the /api/v1 parent.
	pxeRouter.RegisterRoutes(s.router.PathPrefix(iamRESTParentPath).Subrouter())
	s.logger.Info("PXE REST routes registered")
	return nil
}

// pxeRESTCallerBinding authenticates the caller (401 without a credential)
// and publishes it as the request's REST caller and gRPC authorized context,
// so the scope check reuses it and callerTenant binds the call to its tenant.
func pxeRESTCallerBinding(guard *restapi.ScopeGuard) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return guard.Authenticate(func(w http.ResponseWriter, r *http.Request, caller *platformtoken.AuthorizedContext) {
			ctx := context.WithValue(r.Context(), restCallerKey{}, caller)
			ctx = grpcapi.ContextWithAuthorizedContext(ctx, caller)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
