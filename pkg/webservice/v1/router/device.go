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
	attestHandler         device.AttestHandler
	attestCertHandler     device.AttestCertHandler
	WebServiceRouter
}

// SetAttestCertHandler supplies the handler for
// POST /devices/{id}/attest-cert/record. Like the attestation verifier it
// is operator work on the admin gate: it rewrites the trust anchor every
// later quote from the device is verified against. Nil leaves the route
// unregistered.
func (r *DeviceRouter) SetAttestCertHandler(handler device.AttestCertHandler) {
	r.attestCertHandler = handler
}

// NewDeviceRouter creates a DeviceRouter. All handlers except mtlsMiddleware and
// deviceHandler are optional — pass nil to skip those route groups.
// It returns the concrete *DeviceRouter rather than WebServiceRouter because
// the device surface is split by principal (#165): the caller mounts
// RegisterRoutes on a gated router and RegisterMachineFacingRoutes on the
// ungated one, and a single-method interface cannot express that. *DeviceRouter
// still satisfies WebServiceRouter, so existing callers are unaffected.
func NewDeviceRouter(
	mtlsMiddleware middleware.MTLSMiddleware,
	deviceHandler device.RestHandler,
	crudHandler device.DeviceCRUDHandler,
	templateHandler device.TemplateCRUDHandler,
	configDeliveryHandler configdelivery.RestHandler,
	attestHandler device.AttestHandler,
) *DeviceRouter {
	return &DeviceRouter{
		mtlsMiddleware:        mtlsMiddleware,
		deviceHandler:         deviceHandler,
		crudHandler:           crudHandler,
		templateHandler:       templateHandler,
		configDeliveryHandler: configDeliveryHandler,
		attestHandler:         attestHandler,
	}
}

// RegisterRoutes registers the OPERATOR half of the device surface on the
// provided router, which the caller must have gated: device and profile
// CRUD, device templates, profile assignment, and the provisioning session
// views an administrator drives.
//
// The machine-facing half is RegisterMachineFacingRoutes and must not be
// mounted here — every route in it belongs to a device that has no operator
// session, and several are reached before the device has any platform
// credential at all.
func (r *DeviceRouter) RegisterRoutes(router *mux.Router) {
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

	// The provisioning session views and the fulfilment action. Fulfilment
	// binds a profile to a device that is waiting for one, which decides
	// what configuration that machine boots with — an operator decision,
	// and one that answered anonymous callers before #165.
	if r.configDeliveryHandler != nil {
		r.registerProvisioningOperatorRoutes(router)
	}

	// Device attestation verification. Operator work on the ADMIN gate: it
	// reads a device's enrolled attestation key and reports a security
	// verdict about that machine, so it does not belong on the
	// machine-facing half.
	if r.attestHandler != nil {
		router.HandleFunc("/devices/{id}/attest", r.attestHandler.HandleAttestDevice).Methods("POST")
	}

	// Recording a device's attestation certificate without re-enrolling it
	// (#473). Admin gate for the same reason as the verifier above: the
	// recorded certificate is the anchor the verifier chains quotes to.
	if r.attestCertHandler != nil {
		router.HandleFunc("/devices/{id:[0-9]+}/attest-cert/record", r.attestCertHandler.HandleRecordAttestCert).Methods("POST")
	}
}

// RegisterMachineFacingRoutes registers the routes a DEVICE calls, and takes
// the UNGATED router. Each already authenticates by a means appropriate to a
// machine, or is reached before the machine has a credential at all:
//
//   - /device/{profile,activate,heartbeat} verify an mTLS client certificate
//     through the negroni chain below, which is why they are not role-gated.
//   - /provisioning/{config,config/nonce} authenticate by EAB, and
//     /provisioning/sign by EAB plus the EK. A machine at boot has no client
//     certificate — this router said so in terms before #165 — so a role
//     guard in front of them would make provisioning impossible.
//   - /provisioning/sessions/{id}/poll is polled by the provisioning client
//     while it waits for an operator to fulfil its session, so it follows the
//     device-facing half rather than the session views.
//
// Nothing that an operator drives may be added here.
func (r *DeviceRouter) RegisterMachineFacingRoutes(router *mux.Router) {
	if r.deviceHandler != nil {
		r.profile(router)
		r.activate(router)
		r.heartbeat(router)
	}
	if r.configDeliveryHandler != nil {
		r.registerProvisioningDeviceRoutes(router)
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

// POST /api/v1/device/heartbeat - Record the calling device's liveness
// (mTLS; the device identity comes from the verified client certificate)
func (r *DeviceRouter) heartbeat(router *mux.Router) {
	router.Handle("/device/heartbeat", negroni.New(
		negroni.HandlerFunc(r.mtlsMiddleware.Verify),
		negroni.Wrap(http.HandlerFunc(r.deviceHandler.Heartbeat)),
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
	// /devices/templates plural aliases for the same reason — except POST,
	// which the bootstrap seeder router owns outright
	// (pkg/webservice/v1/rest/device, `{role, template}` body). One handler
	// per route: CRUD template creation is singular `/device/templates` only.
	if r.templateHandler != nil {
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

// registerProvisioningDeviceRoutes registers the config-delivery endpoints a
// DEVICE calls. They carry no role gate because a machine at boot has no
// client certificate and no operator session; the handlers authenticate by
// EAB, and SignDigest additionally by the EK.
func (r *DeviceRouter) registerProvisioningDeviceRoutes(router *mux.Router) {
	// POST /api/v1/provisioning/config - Fetch config for device (EAB-authenticated)
	router.HandleFunc("/provisioning/config", r.configDeliveryHandler.FetchConfig).Methods("POST")

	// GET /api/v1/provisioning/config/nonce - Get nonce for replay prevention
	router.HandleFunc("/provisioning/config/nonce", r.configDeliveryHandler.GetNonce).Methods("GET")

	// POST /api/v1/provisioning/sign - Remote Secure Boot DB digest signing (EAB+EK auth)
	router.HandleFunc("/provisioning/sign", r.configDeliveryHandler.SignDigest).Methods("POST")

	// GET /api/v1/provisioning/sessions/{sessionID}/poll - Poll session status.
	// Called by the provisioning client while it waits for an operator to
	// fulfil its session, so it belongs with the device-facing half.
	router.HandleFunc("/provisioning/sessions/{sessionID}/poll", r.configDeliveryHandler.PollSession).Methods("GET")
}

// registerProvisioningOperatorRoutes registers the session surface an
// ADMINISTRATOR drives. The caller must supply a gated router.
//
// Fulfilment is the one that matters: it binds a profile to a device waiting
// for one, which decides what configuration that machine boots with. Before
// #165 an anonymous caller could choose that for any pending session.
func (r *DeviceRouter) registerProvisioningOperatorRoutes(router *mux.Router) {
	// POST /api/v1/provisioning/sessions/{sessionID}/fulfill - Fulfill pending session
	router.HandleFunc("/provisioning/sessions/{sessionID}/fulfill", r.configDeliveryHandler.FulfillSession).Methods("POST")

	// GET /api/v1/provisioning/sessions - List active sessions
	router.HandleFunc("/provisioning/sessions", r.configDeliveryHandler.ListSessions).Methods("GET")

	// GET /api/v1/provisioning/sessions/{sessionID} - Get session by ID
	router.HandleFunc("/provisioning/sessions/{sessionID}", r.configDeliveryHandler.GetSession).Methods("GET")
}
