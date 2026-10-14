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

// Package device provides REST handlers and routing for bootstrap seeder
// device template and profile endpoints. These routes are consumed by the
// bootstrap seeder to upload device templates and create per-node profiles.
package device

import (
	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	// basePath is the device route prefix relative to the parent API
	// subrouter. The parent already mounts at /api/v1, so routes resolve
	// to /api/v1/devices/... at runtime.
	basePath = "/devices"
)

// DeviceRouter provides REST routing for bootstrap seeder device template
// and profile operations.
type DeviceRouter struct {
	handlers *DeviceTemplateHandlers
}

// NewDeviceRouter creates a new DeviceRouter with the given dependencies.
func NewDeviceRouter(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	templateService device.DeviceTemplateService,
	profileService device.DeviceProfileService,
) *DeviceRouter {
	return &DeviceRouter{
		handlers: NewDeviceTemplateHandlers(
			logger,
			responseWriter,
			templateService,
			profileService,
		),
	}
}

// RegisterRoutes registers bootstrap seeder device template routes on the
// provided router. The router parameter is expected to be the /api/v1
// subrouter, so routes are registered under /devices relative to that prefix.
//
// Routes:
//
//	POST /api/v1/devices/templates                     - Upload a device template
//	POST /api/v1/devices/templates/{id}/create-profile - Create a profile from a template
//
// GET /api/v1/devices/config is not among them: it is mounted only on the
// provisioning surface, by RegisterConfigRoute (#177).
func (r *DeviceRouter) RegisterRoutes(router *mux.Router) {
	deviceRouter := router.PathPrefix(basePath).Subrouter()

	deviceRouter.HandleFunc("/templates", r.handlers.HandleUploadTemplate).Methods("POST")
	deviceRouter.HandleFunc("/templates/{id:[0-9]+}/create-profile", r.handlers.HandleCreateProfile).Methods("POST")
}

// RegisterConfigRoute registers the boot-time config fetch on the provided
// /api/v1 subrouter:
//
//	GET /api/v1/devices/config - Get device config by MAC or serial
//
// The route is unauthenticated by design: its caller is a machine that is
// still booting and holds no credential. It is therefore mounted only on a
// webservice whose surface is "provisioning", a listener bound inside the
// isolated provisioning zone (#177). No other listener or transport routes it.
func (r *DeviceRouter) RegisterConfigRoute(router *mux.Router) {
	router.HandleFunc(basePath+"/config", r.handlers.HandleGetConfig).Methods("GET")
}
