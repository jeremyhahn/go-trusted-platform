package daemon

import (
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restdns "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/dns"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// dnsScopeResource is the scope resource of every DNS route: dns:read,
// dns:write or dns:delete. No DNS POST is read-only: Resolve is a GET.
const dnsScopeResource = "dns"

// SetDNSRouterHandlers mounts the DNS routes (zones, records, resolve,
// DNSSEC and registration) at /api/v1/dns on the daemon REST listener.
// server is the DNSServiceServer gRPC, QUIC, MCP and Unix serve, so every
// transport answers alike. Every route authenticates through guard and needs
// the dns:* scope the gRPC catalog gives its rpc.
func (s *RESTServer) SetDNSRouterHandlers(logger *logging.Logger, server platformv1.DNSServiceServer, guard *restapi.ScopeGuard) error {
	switch {
	case logger == nil:
		return ErrDNSRESTUnavailable{Reason: "no logger"}
	case server == nil:
		return ErrDNSRESTUnavailable{Reason: "no DNS service"}
	case guard == nil:
		return ErrDNSRESTUnavailable{Reason: "no REST scope guard"}
	}
	respWriter := response.NewResponseWriter(logger, nil)
	authz := restScopeAuthorization{guard: guard, respWriter: respWriter, routeScope: dnsRouteScope}
	parent := s.router.PathPrefix(iamRESTParentPath).Subrouter()
	parent.Use(authz.authorize)
	// The DNS router mounts its /dns subrouter on the /api/v1 parent.
	restdns.NewDNSRouter(logger, server, respWriter).RegisterRoutes(parent)
	s.logger.Info("DNS REST routes registered")
	return nil
}

// dnsRouteScope is the scope a DNS request needs.
func dnsRouteScope(method, route string) (string, error) {
	action, err := restScopeAction(dnsScopeResource, nil, method, route)
	if err != nil {
		return "", err
	}
	return dnsScopeResource + ":" + action, nil
}
