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
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SetSDNService wires the shared SDN service into the REST handlers.
// Bridge, port and flow routes drive its OVS client; the routes whose state
// the service owns (VLANs) call the service itself, the same instance the
// gRPC, QUIC, MCP and Unix transports serve, so every transport sees one
// state. When svc is nil, handlers are still created so that zone endpoints
// (registered unconditionally in RegisterRoutes) are available; the SDN
// routes return 503. Every route authenticates through guard and needs the
// sdn:* scope the gRPC catalog gives its SDNService rpc; a nil guard is
// refused.
func (s *RESTServer) SetSDNService(svc *SDNService, guard *rest.ScopeGuard) error {
	if guard == nil {
		return ErrSDNRESTUnavailable{Reason: "no REST scope guard"}
	}
	// A nil *SDNService must reach the handlers as a nil interface, so the
	// routes answer 503 rather than dereference it.
	var server platformv1.SDNServiceServer
	if svc != nil {
		server = svc
	}
	authz := restScopeAuthorization{
		guard:      guard,
		respWriter: response.NewResponseWriter(logging.NewFromSlog(s.logger), nil),
		routeScope: sdnRouteScope,
	}
	sdnHandlers := rest.NewSDNHandlers(server, s.logger)
	s.mountOwnedAbsolute(sdnHandlers.RegisterRoutes, authz.authorize)
	s.sdnHandlers = sdnHandlers
	return nil
}

// SetGatewayIPAMService wires IPAM and gateway REST handlers using the provided
// allocator. When allocator is nil, a default in-memory allocator is used so
// that IPAM pool CRUD endpoints work out-of-the-box without a full SDN controller.
// The status and mode routes answer from status; nil reports them not configured.
// Every gateway route runs behind guard and needs the scope the gRPC catalog
// gives its rpc; a nil guard mounts nothing.
func (s *RESTServer) SetGatewayIPAMService(allocator ipam.Allocator, status GatewayStatusController, guard *rest.ScopeGuard) error {
	if guard == nil {
		return ErrGatewayRESTUnavailable{Reason: "no REST scope guard"}
	}
	svc := newGatewayRESTService(allocator, s.logger)
	svc.SetGatewayStatusController(status)
	handlers := rest.NewGatewayHandlers(svc, s.logger)
	s.mountOwnedAbsolute(handlers.RegisterRoutes, s.catalogAuthorization(guard).authorize)
	s.gatewayService = svc
	s.gatewayHandlers = handlers
	s.logger.Info("Gateway REST routes registered (IPAM + gateway status)")
	return nil
}

// errGatewayRoutesNotMounted is returned by the gateway setters that wire a
// service into routes SetGatewayIPAMService has not mounted. They never mount
// the routes themselves, so no gateway route can exist without the guard.
var errGatewayRoutesNotMounted = ErrGatewayRESTUnavailable{Reason: "SetGatewayIPAMService has not mounted the gateway routes"}

// SetGatewaySnapshotService wires the gateway telemetry reader that answers
// the admitted-VTEP REST endpoints. A nil reader leaves them unconfigured.
func (s *RESTServer) SetGatewaySnapshotService(reader GatewaySnapshotReader) error {
	if reader == nil {
		return nil
	}
	if s.gatewayService == nil {
		return errGatewayRoutesNotMounted
	}
	s.gatewayService.reader = reader
	s.logger.Info("Gateway overlay admission REST service wired into gateway handlers")
	return nil
}

// SetGatewayBGPService wires the gateway gRPC service the REST BGP routes
// answer from, so REST reports BGP not configured exactly when gRPC does
// (#65).
func (s *RESTServer) SetGatewayBGPService(controller GatewayBGPController) error {
	if controller == nil {
		return nil
	}
	if s.gatewayService == nil {
		return errGatewayRoutesNotMounted
	}
	s.gatewayService.SetGatewayBGPController(controller)
	s.logger.Info("Gateway BGP REST service wired into gateway handlers")
	return nil
}

// SetGatewayBackends points the gateway REST load-balancer, NAT64 and perf
// routes at the shared gateway service (#660). A backend the service lacks
// leaves its routes returning 503.
func (s *RESTServer) SetGatewayBackends(backends GatewayBackendSource) error {
	if backends == nil {
		return nil
	}
	if s.gatewayService == nil {
		return errGatewayRoutesNotMounted
	}
	s.gatewayService.backends = backends
	s.gatewayHandlers.SetPerfService(newGatewayPerfRESTService(backends))
	s.logger.Info("Gateway LB, NAT64 and perf REST services wired into gateway handlers")
	return nil
}

// SetZoneService wires the zone service into the SDN REST handlers.
// Must be called after SetSDNService.
func (s *RESTServer) SetZoneService(svc gateway.ZoneService) {
	if svc == nil {
		return
	}
	if s.sdnHandlers == nil {
		// Ensure handlers exist even if SetSDNService was never called.
		s.sdnHandlers = rest.NewSDNHandlers(nil, s.logger)
		s.mountOwnedAbsolute(s.sdnHandlers.RegisterRoutes)
	}
	s.sdnHandlers.SetZoneService(svc)
	s.logger.Info("Zone service wired into SDN REST handlers")
}
