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
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
)

// BMCRouter handles BMC-related routes including power control, boot device
// management, virtual media, sensors, system info, certificate management,
// user management, and bare metal provisioning.
type BMCRouter struct {
	handler bmc.RestHandler
	WebServiceRouter
}

// NewBMCRouter creates a BMCRouter with the given handler.
//
// # The caller MUST pass a gated router (#237)
//
// v1Router.bmcRoutes in pkg/webservice/v1/router.go mounts this router on
// the console listener (#1720); the daemon RESTServer mounts the same
// handler when it runs (#232). It must stay on an AUTHENTICATED, role-gated
// router:
//
//	bmcRouter.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
//
// NOT on v1Router.router. RegisterRoutes takes a plain *mux.Router and every
// router in this package was ungated when this file was written, so
// symmetry with its neighbours suggests exactly the wrong call. The routes
// below are POST /bmc/{id}/power, /boot-device, /virtual-media (mount an
// ISO) and /provision: together they are remote physical control of the
// machine, so publishing them to anonymous callers hands over the host, not
// just an API.
//
// The default-deny audit (TestRegisterRoutes_EveryRouteDeniesWithoutCredential
// in pkg/webservice/v1) will fail if this is mounted ungated — but only once
// it is mounted, and only if the suite is run before pushing. This comment
// exists so the gate is the obvious move rather than the correction.
func NewBMCRouter(handler bmc.RestHandler) WebServiceRouter {
	return &BMCRouter{
		handler: handler,
	}
}

// RegisterRoutes registers all BMC routes on the provided router.
func (r *BMCRouter) RegisterRoutes(router *mux.Router) {
	// Power management
	// POST /api/v1/bmc/{profileID}/power - Execute power action (on, off, reset, cycle)
	router.HandleFunc("/bmc/{profileID:[0-9]+}/power", r.handler.PowerAction).Methods("POST")

	// GET /api/v1/bmc/{profileID}/power - Get power status
	router.HandleFunc("/bmc/{profileID:[0-9]+}/power", r.handler.PowerStatus).Methods("GET")

	// Boot device management
	// POST /api/v1/bmc/{profileID}/boot-device - Set boot device
	router.HandleFunc("/bmc/{profileID:[0-9]+}/boot-device", r.handler.SetBootDevice).Methods("POST")

	// GET /api/v1/bmc/{profileID}/boot-device - Get boot device
	router.HandleFunc("/bmc/{profileID:[0-9]+}/boot-device", r.handler.GetBootDevice).Methods("GET")

	// Virtual media management
	// POST /api/v1/bmc/{profileID}/virtual-media - Mount ISO
	router.HandleFunc("/bmc/{profileID:[0-9]+}/virtual-media", r.handler.MountISO).Methods("POST")

	// DELETE /api/v1/bmc/{profileID}/virtual-media - Unmount ISO
	router.HandleFunc("/bmc/{profileID:[0-9]+}/virtual-media", r.handler.UnmountISO).Methods("DELETE")

	// GET /api/v1/bmc/{profileID}/virtual-media - Get virtual media status
	router.HandleFunc("/bmc/{profileID:[0-9]+}/virtual-media", r.handler.VirtualMediaStatus).Methods("GET")

	// Hardware information
	// GET /api/v1/bmc/{profileID}/sensors - Get sensor readings
	router.HandleFunc("/bmc/{profileID:[0-9]+}/sensors", r.handler.GetSensors).Methods("GET")

	// GET /api/v1/bmc/{profileID}/system-info - Get system info
	router.HandleFunc("/bmc/{profileID:[0-9]+}/system-info", r.handler.GetSystemInfo).Methods("GET")

	// Bare metal provisioning
	// POST /api/v1/bmc/{profileID}/provision - Trigger provisioning
	router.HandleFunc("/bmc/{profileID:[0-9]+}/provision", r.handler.Provision).Methods("POST")

	// GET /api/v1/bmc/{profileID}/provision - Get provisioning status
	router.HandleFunc("/bmc/{profileID:[0-9]+}/provision", r.handler.ProvisionStatus).Methods("GET")

	// Enrollment
	// POST /api/v1/bmc/{profileID}/enroll - Enroll the BMC with the platform CA
	router.HandleFunc("/bmc/{profileID:[0-9]+}/enroll", r.handler.EnrollBMC).Methods("POST")

	// Certificate management
	// POST /api/v1/bmc/{profileID}/cert/restore - Restore the BMC web certificate.
	// Registered before the /cert routes, as the daemon REST server does.
	router.HandleFunc("/bmc/{profileID:[0-9]+}/cert/restore", r.handler.RestoreBMC).Methods("POST")

	// GET /api/v1/bmc/{profileID}/cert - Get web TLS certificate metadata
	router.HandleFunc("/bmc/{profileID:[0-9]+}/cert", r.handler.GetWebCertificate).Methods("GET")

	// PUT /api/v1/bmc/{profileID}/cert - Replace web TLS certificate and key
	router.HandleFunc("/bmc/{profileID:[0-9]+}/cert", r.handler.ReplaceWebCertificate).Methods("PUT")

	// User management
	// GET /api/v1/bmc/{profileID}/users - List BMC user accounts
	router.HandleFunc("/bmc/{profileID:[0-9]+}/users", r.handler.ListUsers).Methods("GET")

	// POST /api/v1/bmc/{profileID}/users - Create a new BMC user account
	router.HandleFunc("/bmc/{profileID:[0-9]+}/users", r.handler.CreateUser).Methods("POST")

	// DELETE /api/v1/bmc/{profileID}/users/{slot} - Delete the user occupying a slot
	router.HandleFunc("/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}", r.handler.DeleteUser).Methods("DELETE")

	// PUT /api/v1/bmc/{profileID}/users/{slot}/password - Update user password
	router.HandleFunc("/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/password", r.handler.SetUserPassword).Methods("PUT")

	// PUT /api/v1/bmc/{profileID}/users/{slot}/privilege - Update user privilege
	router.HandleFunc("/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/privilege", r.handler.SetUserPrivilege).Methods("PUT")
}
