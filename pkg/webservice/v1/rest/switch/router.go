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

package switchapi

import (
	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

const basePath = "/switches"

// SwitchRouter provides REST routing for physical switch management.
type SwitchRouter struct {
	handlers *Handlers
	router.WebServiceRouter
}

// NewSwitchRouter creates a new SwitchRouter with the given dependencies.
func NewSwitchRouter(
	logger *logging.Logger,
	switchService device.SwitchServiceProvider,
	responseWriter response.HttpWriter,
) *SwitchRouter {
	return &SwitchRouter{
		handlers: NewHandlers(logger, responseWriter, switchService),
	}
}

// RegisterRoutes registers physical switch management routes on the provided router.
//
// Port names like "Eth1/3" contain slashes, so the subrouter uses UseEncodedPath
// to prevent gorilla/mux from splitting on encoded slashes (%2F). The handlers
// URL-decode path variables before use.
//
// Routes:
//
//	GET  /api/v1/switches/{switch}/ports                  - List all ports
//	GET  /api/v1/switches/{switch}/ports/{port}           - Get port status
//	POST /api/v1/switches/{switch}/ports/{port}/vlan      - Set port VLAN
//	POST /api/v1/switches/{switch}/ports/{port}/enable    - Enable port
//	POST /api/v1/switches/{switch}/ports/{port}/disable   - Disable port
func (r *SwitchRouter) RegisterRoutes(muxRouter *mux.Router) {
	switchRouter := muxRouter.PathPrefix(basePath).Subrouter()
	switchRouter.UseEncodedPath()

	// Port collection
	switchRouter.HandleFunc("/{switch}/ports", r.handlers.ListPorts).Methods("GET")

	// Port instance
	switchRouter.HandleFunc("/{switch}/ports/{port}", r.handlers.GetPortStatus).Methods("GET")

	// Port actions
	switchRouter.HandleFunc("/{switch}/ports/{port}/vlan", r.handlers.SetPortVLAN).Methods("POST")
	switchRouter.HandleFunc("/{switch}/ports/{port}/enable", r.handlers.EnablePort).Methods("POST")
	switchRouter.HandleFunc("/{switch}/ports/{port}/disable", r.handlers.DisablePort).Methods("POST")
}
