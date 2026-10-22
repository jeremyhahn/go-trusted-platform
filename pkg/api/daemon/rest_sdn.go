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
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// SetSDNService wires the shared SDN service into the REST handlers.
// Bridge, port and flow routes drive its OVS client; the routes whose state
// the service owns (VLANs) call the service itself, the same instance the
// gRPC, QUIC, MCP and Unix transports serve, so every transport sees one
// state. When svc is nil, handlers are still created so that zone endpoints
// (registered unconditionally in RegisterRoutes) are available; the SDN
// routes return 503.
func (s *RESTServer) SetSDNService(svc *SDNService) {
	sdnHandlers := rest.NewSDNHandlers(nil, s.logger)
	if svc != nil {
		sdnHandlers = rest.NewSDNHandlers(svc.OVSClient(), s.logger)
		sdnHandlers.SetControlService(svc)
	}
	s.mountOwnedAbsolute(sdnHandlers.RegisterRoutes)
	s.sdnHandlers = sdnHandlers
}

// SetGatewayIPAMService wires IPAM and gateway REST handlers using the provided
// allocator. When allocator is nil, a default in-memory allocator is used so
// that IPAM pool CRUD endpoints work out-of-the-box without a full SDN controller.
// The status and mode routes answer from status; nil reports them not configured.
func (s *RESTServer) SetGatewayIPAMService(allocator ipam.Allocator, status GatewayStatusController) {
	svc := newGatewayRESTService(allocator, s.logger)
	svc.SetGatewayStatusController(status)
	handlers := rest.NewGatewayHandlers(svc, s.logger)
	s.mountOwnedAbsolute(handlers.RegisterRoutes)
	s.gatewayService = svc
	s.gatewayHandlers = handlers
	s.logger.Info("Gateway REST routes registered (IPAM + gateway status)")
}

// SetGatewaySnapshotService wires the gateway telemetry reader that answers
// the admitted-VTEP REST endpoints. A nil reader leaves them unconfigured.
func (s *RESTServer) SetGatewaySnapshotService(reader GatewaySnapshotReader) {
	if reader == nil {
		return
	}
	if s.gatewayService == nil {
		s.SetGatewayIPAMService(nil, nil)
	}
	s.gatewayService.reader = reader
	s.logger.Info("Gateway overlay admission REST service wired into gateway handlers")
}

// SetGatewayBGPService wires the gateway gRPC service the REST BGP routes
// answer from, so REST reports BGP not configured exactly when gRPC does
// (#65).
func (s *RESTServer) SetGatewayBGPService(controller GatewayBGPController) {
	if controller == nil {
		return
	}
	if s.gatewayService == nil {
		s.SetGatewayIPAMService(nil, nil)
	}
	s.gatewayService.SetGatewayBGPController(controller)
	s.logger.Info("Gateway BGP REST service wired into gateway handlers")
}

// SetGatewayBackends points the gateway REST load-balancer, NAT64 and perf
// routes at the shared gateway service (#660). A backend the service lacks
// leaves its routes returning 503.
func (s *RESTServer) SetGatewayBackends(backends GatewayBackendSource) {
	if backends == nil {
		return
	}
	if s.gatewayService == nil {
		s.SetGatewayIPAMService(nil, nil)
	}
	s.gatewayService.backends = backends
	s.gatewayHandlers.SetPerfService(newGatewayPerfRESTService(backends))
	s.logger.Info("Gateway LB, NAT64 and perf REST services wired into gateway handlers")
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
