package daemon

import (
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
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
// the dns:* scope the gRPC catalog gives its rpc. The DNS service authorizes
// against its own configured tenant, backendTenantID, so a caller bound to
// any other tenant is refused before it reaches server.
func (s *RESTServer) SetDNSRouterHandlers(logger *logging.Logger, server platformv1.DNSServiceServer, guard *restapi.ScopeGuard, backendTenantID string) error {
	switch {
	case logger == nil:
		return ErrDNSRESTUnavailable{Reason: "no logger"}
	case server == nil:
		return ErrDNSRESTUnavailable{Reason: "no DNS service"}
	case guard == nil:
		return ErrDNSRESTUnavailable{Reason: "no REST scope guard"}
	}
	respWriter := response.NewResponseWriter(logger, nil)
	authz := restScopeAuthorization{
		guard:      guard,
		respWriter: respWriter,
		routeScope: dnsRouteScope,
		callerGate: func(callerTenantID string) error {
			return dnsRouterTenantDecision(backendTenantID, callerTenantID)
		},
	}
	parent := s.router.PathPrefix(iamRESTParentPath).Subrouter()
	parent.Use(authz.authorize)
	// The DNS router mounts its /dns subrouter on the /api/v1 parent.
	restdns.NewDNSRouter(logger, server, respWriter).RegisterRoutes(parent)
	s.logger.Info("DNS REST routes registered")
	return nil
}

// ErrDNSRouterTenantUnbound refuses a caller bound to a tenant other than
// the DNS backend's. The DNS service serves the zones of its configured
// tenant only, so serving such a caller would expose another tenant's zones.
type ErrDNSRouterTenantUnbound struct {
	Tenant  string
	Backend string
}

func (e ErrDNSRouterTenantUnbound) Error() string {
	return "DNS router: tenant " + e.Tenant + " refused: the DNS backend serves tenant " + e.Backend
}

// dnsRouterTenantDecision admits a caller with no tenant or the DNS
// backend's tenant, and refuses every other tenant. An unset backend tenant
// admits no tenant-bound caller (tenant.IsSystemTenant).
func dnsRouterTenantDecision(backendTenantID, callerTenantID string) error {
	if callerTenantID == "" || tenant.IsSystemTenant(backendTenantID, callerTenantID) {
		return nil
	}
	return ErrDNSRouterTenantUnbound{Tenant: callerTenantID, Backend: backendTenantID}
}

// dnsRouteScope is the scope a DNS request needs.
func dnsRouteScope(method, route string) (string, error) {
	action, err := restScopeAction(dnsScopeResource, nil, method, route)
	if err != nil {
		return "", err
	}
	return dnsScopeResource + ":" + action, nil
}
