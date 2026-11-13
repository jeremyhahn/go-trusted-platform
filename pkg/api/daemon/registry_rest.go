package daemon

import (
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restregistry "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/registry"
)

// registryScopeResource is the scope resource the registry rpcs carry on
// every transport (registry:read, registry:write, registry:delete).
const registryScopeResource = "registry"

// SetRegistryRouterHandlers mounts the registry routes on the daemon REST
// listener, serving the same RegistryService the gRPC, QUIC, MCP and Unix
// transports serve. Every route passes the scope guard first.
func (s *RESTServer) SetRegistryRouterHandlers(logger *logging.Logger, service grpcapi.RegistryService, guard *restapi.ScopeGuard) error {
	switch {
	case logger == nil:
		return ErrRegistryRESTUnavailable{Reason: "no logger"}
	case service == nil:
		return ErrRegistryRESTUnavailable{Reason: "no registry service"}
	case guard == nil:
		return ErrRegistryRESTUnavailable{Reason: "no REST scope guard"}
	}
	respWriter := response.NewResponseWriter(logger, nil)
	authz := restScopeAuthorization{guard: guard, respWriter: respWriter, routeScope: registryRouteScope}
	parent := s.router.PathPrefix(iamRESTParentPath).Subrouter()
	parent.Use(authz.authorize)
	// The registry router mounts its /compute/images subrouter on the /api/v1 parent.
	restregistry.NewRouter(logger, service, respWriter).RegisterRoutes(parent)
	s.logger.Info("registry REST routes registered")
	return nil
}

// registryRouteScope maps a registry route to its scope: GET reads, POST
// (push) writes and DELETE deletes, as the gRPC catalog does.
func registryRouteScope(method, route string) (string, error) {
	action, err := restScopeAction(registryScopeResource, nil, method, route)
	if err != nil {
		return "", err
	}
	return registryScopeResource + ":" + action, nil
}
