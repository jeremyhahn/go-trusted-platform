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

	"github.com/gorilla/mux"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restgateway "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/gateway"
)

const (
	// gatewayStateReadScope reads the fleet's reported gateway state: the
	// scope GetGatewaySnapshot, the gRPC read of the same store, requires.
	gatewayStateReadScope = "sdn:read"
	// gatewayStateForgetScope forgets one gateway's reported state.
	gatewayStateForgetScope = "sdn:delete"
)

// SetGatewayControlPlane mounts the gateway ⇄ control-plane liaison
// (docs/gateway/api.md §8) on the daemon's REST router, the listener a
// gateway's control-plane base-url names. The handlers are the webservice's
// (pkg/webservice/v1/rest/gateway), so both listeners speak one wire format.
//
// The gatewayd-facing half (telemetry, desired-config, vpn-leases)
// authenticates itself: each route binds the request's gateway id to the
// verified client certificate's Common Name. The operator half, the
// fleet-wide /gateway/state surface, requires sdn:read to read and
// sdn:delete to forget, checked by the daemon's REST guard.
//
// With neither a store nor a desired-config source nothing is mounted, as
// on the webservice router. A nil leases sink leaves the vpn-leases routes
// answering ErrGatewayControlNotConfigured.
func (s *RESTServer) SetGatewayControlPlane(
	store restgateway.GatewayStateStore,
	cfgSource restgateway.DesiredConfigSource,
	leases restgateway.VPNLeaseSink,
	guard *restapi.ScopeGuard,
) {
	if store == nil && cfgSource == nil {
		return
	}
	logger := logging.NewFromSlog(s.logger)
	cp := restgateway.NewControlPlane(logger, store, cfgSource, response.NewResponseWriter(logger, nil))
	cp.SetVPNLeaseSink(leases)

	cp.RegisterGatewayFacingRoutes(s.router.PathPrefix(restBasePath).Subrouter())

	operator := s.router.PathPrefix(restBasePath).Subrouter()
	operator.Use(gatewayStateGuard(guard))
	cp.RegisterRoutes(operator)

	s.logger.Info("Gateway control-plane REST routes registered")
}

// gatewayStateGuard requires gatewayStateForgetScope for a DELETE and
// gatewayStateReadScope for every other method of the operator half.
func gatewayStateGuard(guard *restapi.ScopeGuard) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		read := guard.Require(gatewayStateReadScope, next.ServeHTTP)
		forget := guard.Require(gatewayStateForgetScope, next.ServeHTTP)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				forget(w, r)
				return
			}
			read(w, r)
		})
	}
}
