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
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// SetSDNService sets the SDN service for REST handlers.
// This allows SDN bridge, port, flow, and policy operations via REST API.
// The ovs.ClientInterface satisfies rest.SDNServiceInterface.
func (s *RESTServer) SetSDNService(svc ovs.ClientInterface) {
	if svc != nil {
		sdnHandlers := rest.NewSDNHandlers(svc, s.logger)
		sdnHandlers.RegisterRoutes(s.router)
		s.logger.Info("SDN REST routes registered")
	}
}
