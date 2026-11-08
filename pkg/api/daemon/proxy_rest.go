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
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// SetProxyService wires the shared proxy configuration service into the
// daemon's REST API. The svc argument is satisfied by the shared
// ProxyGRPCService so REST, gRPC, QUIC and MCP all serve the same store
// with identical error mapping. Each route runs behind guard and needs the
// scope the gRPC catalog gives its rpc; a nil guard is refused with
// ErrProxyRESTUnavailable.
func (s *RESTServer) SetProxyService(svc rest.ProxyServiceBackend, guard *rest.ScopeGuard) error {
	if guard == nil {
		return ErrProxyRESTUnavailable{Reason: "no REST scope guard"}
	}
	if svc == nil {
		return nil
	}
	handlers := rest.NewProxyHandlers(svc, s.logger)
	s.mountOwnedAbsolute(handlers.RegisterRoutes, s.catalogAuthorization(guard).authorize)
	s.logger.Info("Proxy REST routes registered")
	return nil
}
