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

package router

import (
	"net/http"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
)

// DeviceRouter handles device-related routes including legacy mTLS endpoints,
// CRUD operations for devices/profiles/templates, and provisioning config delivery.
// All handler fields are optional — routes are only registered for non-nil handlers.
type DeviceRouter struct {
	mtlsMiddleware        middleware.MTLSMiddleware
	deviceHandler         device.RestHandler
	crudHandler           device.DeviceCRUDHandler
	templateHandler       device.TemplateCRUDHandler
	configDeliveryHandler configdelivery.RestHandler
	WebServiceRouter
}

// NewDeviceRouter creates a DeviceRouter. All handlers except mtlsMiddleware and
// deviceHandler are optional — pass nil to skip those route groups.
func NewDeviceRouter(
	mtlsMiddleware middleware.MTLSMiddleware,
	deviceHandler device.RestHandler,
	crudHandler device.DeviceCRUDHandler,
	templateHandler device.TemplateCRUDHandler,
	configDeliveryHandler configdelivery.RestHandler,
) WebServiceRouter {
	return &DeviceRouter{
		mtlsMiddleware:        mtlsMiddleware,
		deviceHandler:         deviceHandler,
		crudHandler:           crudHandler,
		templateHandler:       templateHandler,
		configDeliveryHandler: configDeliveryHandler,
	}
}

// RegisterRoutes registers all device routes.
func (r *DeviceRouter) RegisterRoutes(router *mux.Router) {
	// Legacy mTLS-protected endpoints (require deviceHandler)
	if r.deviceHandler != nil {
		r.profile(router)
		r.activate(router)
	}

	// CRUD endpoints (if handler is available)
	if r.crudHandler != nil {
		r.registerDeviceCRUD(router)
		r.registerProfileCRUD(router)
	}

	// Template endpoints (if handler is available)
	if r.templateHandler != nil {
		r.registerTemplateCRUD(router)
		r.registerConfigDeliveryRoutes(router)
	}

	// Provisioning config delivery endpoints (unprotected - no mTLS)
	if r.configDeliveryHandler != nil {
		r.registerProvisioningRoutes(router)
	}
}

// GET /api/v1/device/profile - Get device profile via mTLS
func (r *DeviceRouter) profile(router *mux.Router) {
	router.Handle("/device/profile", negroni.New(
		negroni.HandlerFunc(r.mtlsMiddleware.Verify),
		negroni.Wrap(http.HandlerFunc(r.deviceHandler.GetProfile)),
	)).Methods("GET")
}

// POST /api/v1/device/activate - Activate device and transition to trusted zone
func (r *DeviceRouter) activate(router *mux.Router) {
	router.Handle("/device/activate", negroni.New(
		negroni.HandlerFunc(r.mtlsMiddleware.Verify),
		negroni.Wrap(http.HandlerFunc(r.deviceHandler.Activate)),
	)).Methods("POST")
}

// registerDeviceCRUD registers device CRUD endpoints.
func (r *DeviceRouter) registerDeviceCRUD(router *mux.Router) {
	// Device CRUD operations
	// POST /api/v1/devices - Create device
	router.HandleFunc("/devices", r.crudHandler.CreateDevice).Methods("POST")

	// GET /api/v1/devices - List devices
	router.HandleFunc("/devices", r.crudHandler.ListDevices).Methods("GET")

	// GET /api/v1/devices/count - Count devices
	router.HandleFunc("/devices/count", r.crudHandler.CountDevices).Methods("GET")

	// GET /api/v1/devices/serial/{serial} - Find device by serial
	router.HandleFunc("/devices/serial/{serial}", r.crudHandler.FindDeviceBySerial).Methods("GET")

	// GET /api/v1/devices/{id} - Get device
	router.HandleFunc("/devices/{id:[0-9]+}", r.crudHandler.GetDevice).Methods("GET")

	// PUT /api/v1/devices/{id} - Update device
	router.HandleFunc("/devices/{id:[0-9]+}", r.crudHandler.UpdateDevice).Methods("PUT")

	// DELETE /api/v1/devices/{id} - Delete device
	router.HandleFunc("/devices/{id:[0-9]+}", r.crudHandler.DeleteDevice).Methods("DELETE")
}

// registerProfileCRUD registers device profile CRUD endpoints.
func (r *DeviceRouter) registerProfileCRUD(router *mux.Router) {
	// Profile CRUD operations
	// POST /api/v1/device/profiles - Create profile
	router.HandleFunc("/device/profiles", r.crudHandler.CreateProfile).Methods("POST")

	// GET /api/v1/device/profiles - List profiles
	router.HandleFunc("/device/profiles", r.crudHandler.ListProfiles).Methods("GET")

	// /devices/profiles aliases match the WebUI's plural-noun convention
	// — the dashboard hits `/api/v1/devices/profiles` while the platform
	// originally exposed singular `/api/v1/device/profiles`. Both forms
	// must dispatch to the same handler so REST and SDK callers agree.
	router.HandleFunc("/devices/profiles", r.crudHandler.CreateProfile).Methods("POST")
	router.HandleFunc("/devices/profiles", r.crudHandler.ListProfiles).Methods("GET")
	router.HandleFunc("/devices/profiles/{id:[0-9]+}", r.crudHandler.GetProfileByID).Methods("GET")
	router.HandleFunc("/devices/profiles/{id:[0-9]+}", r.crudHandler.UpdateProfile).Methods("PUT")
	router.HandleFunc("/devices/profiles/{id:[0-9]+}", r.crudHandler.DeleteProfile).Methods("DELETE")
	// /devices/templates plural alias for the same reason. The SDK
	// (sdk/javascript/src/services/device-service.ts) calls
	// `/v1/devices/templates` while the legacy REST surface used
	// `/v1/device/templates`. Both must work.
	if r.templateHandler != nil {
		router.HandleFunc("/devices/templates", r.templateHandler.CreateTemplate).Methods("POST")
		router.HandleFunc("/devices/templates", r.templateHandler.ListTemplates).Methods("GET")
		router.HandleFunc("/devices/templates/{id:[0-9]+}", r.templateHandler.GetTemplate).Methods("GET")
		router.HandleFunc("/devices/templates/{id:[0-9]+}", r.templateHandler.UpdateTemplate).Methods("PUT")
		router.HandleFunc("/devices/templates/{id:[0-9]+}", r.templateHandler.DeleteTemplate).Methods("DELETE")
	}

	// GET /api/v1/device/profiles/count - Count profiles
	router.HandleFunc("/device/profiles/count", r.crudHandler.CountProfiles).Methods("GET")

	// POST /api/v1/device/profiles/match - Find matching profile
	router.HandleFunc("/device/profiles/match", r.crudHandler.FindMatchingProfile).Methods("POST")

	// GET /api/v1/device/profiles/serial/{serial} - Find profile by serial
	router.HandleFunc("/device/profiles/serial/{serial}", r.crudHandler.FindProfileBySerial).Methods("GET")

	// GET /api/v1/device/profiles/mac/{mac} - Find profile by MAC
	router.HandleFunc("/device/profiles/mac/{mac}", r.crudHandler.FindProfileByMAC).Methods("GET")

	// GET /api/v1/device/profiles/{id} - Get profile
	router.HandleFunc("/device/profiles/{id:[0-9]+}", r.crudHandler.GetProfileByID).Methods("GET")

	// PUT /api/v1/device/profiles/{id} - Update profile
	router.HandleFunc("/device/profiles/{id:[0-9]+}", r.crudHandler.UpdateProfile).Methods("PUT")

	// DELETE /api/v1/device/profiles/{id} - Delete profile
	router.HandleFunc("/device/profiles/{id:[0-9]+}", r.crudHandler.DeleteProfile).Methods("DELETE")

	// POST /api/v1/device/activate-json - Alternative activation endpoint with JSON body
	router.HandleFunc("/device/activate-json", r.crudHandler.ActivateDevice).Methods("POST")
}

// registerTemplateCRUD registers device template CRUD endpoints.
func (r *DeviceRouter) registerTemplateCRUD(router *mux.Router) {
	// Template CRUD operations
	// POST /api/v1/device/templates - Create template
	router.HandleFunc("/device/templates", r.templateHandler.CreateTemplate).Methods("POST")

	// GET /api/v1/device/templates - List templates
	router.HandleFunc("/device/templates", r.templateHandler.ListTemplates).Methods("GET")

	// GET /api/v1/device/templates/name/{name} - Find template by name
	router.HandleFunc("/device/templates/name/{name}", r.templateHandler.FindTemplateByName).Methods("GET")

	// GET /api/v1/device/templates/{id} - Get template
	router.HandleFunc("/device/templates/{id:[0-9]+}", r.templateHandler.GetTemplate).Methods("GET")

	// PUT /api/v1/device/templates/{id} - Update template
	router.HandleFunc("/device/templates/{id:[0-9]+}", r.templateHandler.UpdateTemplate).Methods("PUT")

	// DELETE /api/v1/device/templates/{id} - Delete template
	router.HandleFunc("/device/templates/{id:[0-9]+}", r.templateHandler.DeleteTemplate).Methods("DELETE")

	// POST /api/v1/device/templates/{id}/create-profile - Create profile from template
	router.HandleFunc("/device/templates/{id:[0-9]+}/create-profile", r.templateHandler.CreateProfileFromTemplate).Methods("POST")
}

// registerConfigDeliveryRoutes registers config delivery endpoints for profile
// lookup and assignment. These routes require authentication (mTLS).
func (r *DeviceRouter) registerConfigDeliveryRoutes(router *mux.Router) {
	// GET /api/v1/device/profiles/find-config - Find config for device by identity
	router.HandleFunc("/device/profiles/find-config", r.templateHandler.FindConfigForDevice).Methods("GET")

	// POST /api/v1/device/profiles/{id}/assign - Assign profile to device
	router.HandleFunc("/device/profiles/{id:[0-9]+}/assign", r.templateHandler.AssignProfileToDevice).Methods("POST")

	// POST /api/v1/device/profiles/{id}/unassign - Clear profile's device binding
	router.HandleFunc("/device/profiles/{id:[0-9]+}/unassign", r.templateHandler.UnassignProfileFromDevice).Methods("POST")
}

// registerProvisioningRoutes registers config delivery provisioning endpoints.
// These routes are UNPROTECTED (no mTLS) since devices at boot have no client cert.
func (r *DeviceRouter) registerProvisioningRoutes(router *mux.Router) {
	// POST /api/v1/provisioning/config - Fetch config for device (EAB-authenticated)
	router.HandleFunc("/provisioning/config", r.configDeliveryHandler.FetchConfig).Methods("POST")

	// GET /api/v1/provisioning/config/nonce - Get nonce for replay prevention
	router.HandleFunc("/provisioning/config/nonce", r.configDeliveryHandler.GetNonce).Methods("GET")

	// POST /api/v1/provisioning/sign - Remote Secure Boot DB digest signing (EAB+EK auth)
	router.HandleFunc("/provisioning/sign", r.configDeliveryHandler.SignDigest).Methods("POST")

	// GET /api/v1/provisioning/sessions/{sessionID}/poll - Poll session status
	router.HandleFunc("/provisioning/sessions/{sessionID}/poll", r.configDeliveryHandler.PollSession).Methods("GET")

	// POST /api/v1/provisioning/sessions/{sessionID}/fulfill - Fulfill pending session
	router.HandleFunc("/provisioning/sessions/{sessionID}/fulfill", r.configDeliveryHandler.FulfillSession).Methods("POST")

	// GET /api/v1/provisioning/sessions - List active sessions
	router.HandleFunc("/provisioning/sessions", r.configDeliveryHandler.ListSessions).Methods("GET")

	// GET /api/v1/provisioning/sessions/{sessionID} - Get session by ID
	router.HandleFunc("/provisioning/sessions/{sessionID}", r.configDeliveryHandler.GetSession).Methods("GET")
}
