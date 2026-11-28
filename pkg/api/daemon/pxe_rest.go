package daemon

import (
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
	pxeRouter := restpxe.NewPXERouter(logger, server, response.NewResponseWriter(logger, nil), false)
	pxeRouter.SetScopeAuthorizer(restScopeAuthorizer{guard: guard})
	// The PXE router's paths are relative to the /api/v1 parent.
	pxeRouter.RegisterRoutes(s.router.PathPrefix(iamRESTParentPath).Subrouter())
	s.logger.Info("PXE REST routes registered")
	return nil
}
