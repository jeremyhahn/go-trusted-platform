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
// server, and the report and caller-policy routes over reporting: the report
// routes answer 503 without a report cache, and the caller-policy route
// describes reporting.Policy whether or not a report cache is set. Every route authenticates through guard and needs the
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
	// Every reporting handle is optional. The callers router describes the
	// caller policy whenever one is configured, with or without a report
	// cache; with no handle at all it mounts on nil and admits nobody. The
	// reports router mounts on nil without a report cache, so its routes
	// answer 503.
	var callers *restattestation.Reporting
	if reporting.Reports != nil || reporting.Refresher != nil || reporting.Policy != nil {
		callers = &restattestation.Reporting{Reports: reporting.Reports, Refresher: reporting.Refresher, Policy: reporting.Policy}
	}
	var reports *restattestation.Reporting
	if reporting.Reports != nil {
		reports = callers
	}
	restattestation.NewReportsRouter(logger, reports, respWriter).RegisterRoutes(parent)
	restattestation.NewCallersRouter(callers, respWriter).RegisterRoutes(parent)
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
