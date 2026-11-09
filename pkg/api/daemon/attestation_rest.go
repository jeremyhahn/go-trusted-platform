package daemon

import (
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// attestationScopeResource is the scope resource of every /api/v1/attestation
// route: attestation:read, attestation:write or attestation:delete.
const attestationScopeResource = "attestation"

// attestationReadOnlyPosts are the attestation POST routes that only evaluate
// a request body, so they need attestation:read, as gRPC VerifyManifest and
// VerifyAttestationQuote do.
var attestationReadOnlyPosts = []string{
	"/attestation/manifests/verify",
	"/attestation/quote/verify",
}

// SetAttestationRouterHandlers mounts the attestation manifest and quote
// verification routes at /api/v1/attestation on the daemon REST listener over
// server, and the report and caller-policy routes when reporting holds a
// report cache. Every route authenticates through guard and needs the
// attestation:* scope the gRPC catalog gives its rpc. A nil server mounts
// nothing: the node runs no attestation service.
func (s *RESTServer) SetAttestationRouterHandlers(logger *logging.Logger, server platformv1.AttestationServiceServer, reporting ReportingHandles, guard *restapi.ScopeGuard) error {
	switch {
	case logger == nil:
		return ErrAttestationRESTUnavailable{Reason: "no logger"}
	case guard == nil:
		return ErrAttestationRESTUnavailable{Reason: "no REST scope guard"}
	case server == nil:
		return nil
	}
	respWriter := response.NewResponseWriter(logger, nil)
	authz := restScopeAuthorization{guard: guard, respWriter: respWriter, routeScope: attestationRouteScope}
	parent := s.router.PathPrefix(iamRESTParentPath).Subrouter()
	parent.Use(authz.authorize)
	// The attestation routers' /attestation base path is relative to the
	// /api/v1 parent.
	restattestation.NewAttestationServerRouter(logger, server, respWriter).RegisterRoutes(parent)
	// Without a report cache the routers still mount with a nil Reporting:
	// the reports routes answer 503 and the caller policy admits nobody.
	var rep *restattestation.Reporting
	if reporting.Reports != nil {
		rep = &restattestation.Reporting{Reports: reporting.Reports, Refresher: reporting.Refresher, Policy: reporting.Policy}
	}
	restattestation.NewReportsRouter(logger, rep, respWriter).RegisterRoutes(parent)
	restattestation.NewCallersRouter(rep, respWriter).RegisterRoutes(parent)
	s.logger.Info("Attestation REST routes registered", "reports", reporting.Reports != nil)
	return nil
}

// attestationRouteScope is the scope an attestation router request needs.
func attestationRouteScope(method, route string) (string, error) {
	action, err := restScopeAction(attestationScopeResource, attestationReadOnlyPosts, method, route)
	if err != nil {
		return "", err
	}
	return attestationScopeResource + ":" + action, nil
}
