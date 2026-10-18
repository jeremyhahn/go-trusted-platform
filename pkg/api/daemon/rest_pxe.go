// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package daemon

import (
	"net/http"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restpxe "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/pxe"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SetPXEHandlers mounts the PXE REST surface on the daemon REST listener:
// the operator routes under /api/v1/pxe and the provisioning gateway's
// device reports under /api/v1/provisioning/devices, the same routes the
// webservice mounts (pkg/webservice/v1/router.go pxeRoutes). Each route
// calls server, the PXEService servicer gRPC, QUIC and MCP serve, and takes
// the pxe:* or provisioning:write scope its RPC takes on gRPC.
//
// A servicer without a backend still mounts: every route then answers 503
// SERVICE_NOT_CONFIGURED, as the other transports do, rather than 404.
//
// The install-completion webhook is not mounted: platformd has no pxe:
// section to enable it, and the webservice leaves it off the same way.
func (s *RESTServer) SetPXEHandlers(server platformv1.PXEServiceServer, guard *restapi.ScopeGuard) {
	if server == nil {
		return
	}
	logger := logging.NewFromSlog(s.logger)
	router := restpxe.NewPXERouter(logger, server, response.NewResponseWriter(logger, nil), false)
	router.SetScopeAuthorizer(scopeGuardAuthorizer{guard: guard})

	base := s.router.PathPrefix(restBasePath).Subrouter()
	router.RegisterRoutes(base)
	router.RegisterGatewayRoutes(base)
	s.logger.Info("PXE REST routes registered")
}

// scopeGuardAuthorizer presents the daemon's ScopeGuard as the
// middleware.ScopeAuthorizer the webservice routers take. A nil guard
// denies every request.
type scopeGuardAuthorizer struct {
	guard *restapi.ScopeGuard
}

// RequireScope wraps next in the guard's check for scope.
func (a scopeGuardAuthorizer) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return a.guard.Require(scope, next.ServeHTTP)
	}
}
