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
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
)

// BMC operation scopes. Each REST route takes the scope its gRPC twin takes
// in pkg/api/grpc/method_permissions.go (#2021).
const (
	bmcReadScope  = "bmc:read"
	bmcWriteScope = "bmc:write"
	bmcPowerScope = "bmc:power"
	bmcMediaScope = "bmc:media"
	bmcAdminScope = "bmc:admin"
)

// maxPowerActionBody bounds the power request body read by the scope check.
const maxPowerActionBody = 64 << 10

// BMCRouter handles BMC-related routes including power control, boot device
// management, virtual media, sensors, system info, certificate management,
// user management, and bare metal provisioning.
type BMCRouter struct {
	handler         bmc.RestHandler
	scopeAuthorizer middleware.ScopeAuthorizer
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
func NewBMCRouter(handler bmc.RestHandler) *BMCRouter {
	return &BMCRouter{
		handler: handler,
	}
}

// SetScopeAuthorizer enables per-route operation scope checks. With none
// configured (legacy JWT auth) the routes are gated by role and tenant only.
func (r *BMCRouter) SetScopeAuthorizer(authorizer middleware.ScopeAuthorizer) {
	r.scopeAuthorizer = authorizer
}

// requireScope wraps handler in the scope check when one is configured.
func (r *BMCRouter) requireScope(scope string, handler http.HandlerFunc) http.Handler {
	if r.scopeAuthorizer == nil {
		return handler
	}
	return r.scopeAuthorizer.RequireScope(scope)(handler)
}

// powerActionScope requires the scope of the gRPC RPC the requested action
// maps to: bmc:write for "on" (PowerOn), bmc:power for everything else
// (PowerOff, PowerReset, PowerCycle, and any unknown, empty or undecodable
// action, failing closed). The body is restored so the handler decodes it
// unchanged.
func (r *BMCRouter) powerActionScope(handler http.HandlerFunc) http.Handler {
	if r.scopeAuthorizer == nil {
		return handler
	}
	writeGate := r.scopeAuthorizer.RequireScope(bmcWriteScope)(handler)
	powerGate := r.scopeAuthorizer.RequireScope(bmcPowerScope)(handler)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var buf []byte
		if req.Body != nil {
			read, err := io.ReadAll(io.LimitReader(req.Body, maxPowerActionBody))
			if err != nil {
				read = nil
			}
			buf = read
			req.Body = io.NopCloser(bytes.NewReader(buf))
		}
		var action bmc.PowerActionRequest
		if json.Unmarshal(buf, &action) == nil && action.Action == "on" {
			writeGate.ServeHTTP(w, req)
			return
		}
		powerGate.ServeHTTP(w, req)
	})
}

// RegisterRoutes registers all BMC routes on the provided router.
func (r *BMCRouter) RegisterRoutes(router *mux.Router) {
	const (
		profile = "/bmc/{profileID:[0-9]+}"
		slot    = profile + "/users/{slot:[0-9]+}"
	)

	// Power management
	// POST /api/v1/bmc/{profileID}/power - Execute power action (on, off, reset, cycle)
	router.Handle(profile+"/power", r.powerActionScope(r.handler.PowerAction)).Methods("POST")

	// GET /api/v1/bmc/{profileID}/power - Get power status
	router.Handle(profile+"/power", r.requireScope(bmcReadScope, r.handler.PowerStatus)).Methods("GET")

	// Boot device management
	// POST /api/v1/bmc/{profileID}/boot-device - Set boot device
	router.Handle(profile+"/boot-device", r.requireScope(bmcWriteScope, r.handler.SetBootDevice)).Methods("POST")

	// GET /api/v1/bmc/{profileID}/boot-device - Get boot device
	router.Handle(profile+"/boot-device", r.requireScope(bmcReadScope, r.handler.GetBootDevice)).Methods("GET")

	// Virtual media management
	// POST /api/v1/bmc/{profileID}/virtual-media - Mount ISO
	router.Handle(profile+"/virtual-media", r.requireScope(bmcMediaScope, r.handler.MountISO)).Methods("POST")

	// DELETE /api/v1/bmc/{profileID}/virtual-media - Unmount ISO
	router.Handle(profile+"/virtual-media", r.requireScope(bmcMediaScope, r.handler.UnmountISO)).Methods("DELETE")

	// GET /api/v1/bmc/{profileID}/virtual-media - Get virtual media status
	router.Handle(profile+"/virtual-media", r.requireScope(bmcReadScope, r.handler.VirtualMediaStatus)).Methods("GET")

	// Hardware information
	// GET /api/v1/bmc/{profileID}/sensors - Get sensor readings
	router.Handle(profile+"/sensors", r.requireScope(bmcReadScope, r.handler.GetSensors)).Methods("GET")

	// GET /api/v1/bmc/{profileID}/system-info - Get system info
	router.Handle(profile+"/system-info", r.requireScope(bmcReadScope, r.handler.GetSystemInfo)).Methods("GET")

	// Bare metal provisioning
	// POST /api/v1/bmc/{profileID}/provision - Trigger provisioning
	router.Handle(profile+"/provision", r.requireScope(bmcAdminScope, r.handler.Provision)).Methods("POST")

	// GET /api/v1/bmc/{profileID}/provision - Get provisioning status
	router.Handle(profile+"/provision", r.requireScope(bmcReadScope, r.handler.ProvisionStatus)).Methods("GET")

	// Enrollment
	// POST /api/v1/bmc/{profileID}/enroll - Enroll the BMC with the platform CA
	router.Handle(profile+"/enroll", r.requireScope(bmcAdminScope, r.handler.EnrollBMC)).Methods("POST")

	// Certificate management
	// POST /api/v1/bmc/{profileID}/cert/restore - Restore the BMC web certificate.
	// Registered before the /cert routes, as the daemon REST server does.
	router.Handle(profile+"/cert/restore", r.requireScope(bmcAdminScope, r.handler.RestoreBMC)).Methods("POST")

	// GET /api/v1/bmc/{profileID}/cert - Get web TLS certificate metadata
	router.Handle(profile+"/cert", r.requireScope(bmcReadScope, r.handler.GetWebCertificate)).Methods("GET")

	// PUT /api/v1/bmc/{profileID}/cert - Replace web TLS certificate and key
	router.Handle(profile+"/cert", r.requireScope(bmcAdminScope, r.handler.ReplaceWebCertificate)).Methods("PUT")

	// User management
	// GET /api/v1/bmc/{profileID}/users - List BMC user accounts
	router.Handle(profile+"/users", r.requireScope(bmcReadScope, r.handler.ListUsers)).Methods("GET")

	// POST /api/v1/bmc/{profileID}/users - Create a new BMC user account
	router.Handle(profile+"/users", r.requireScope(bmcAdminScope, r.handler.CreateUser)).Methods("POST")

	// DELETE /api/v1/bmc/{profileID}/users/{slot} - Delete the user occupying a slot
	router.Handle(slot, r.requireScope(bmcAdminScope, r.handler.DeleteUser)).Methods("DELETE")

	// PUT /api/v1/bmc/{profileID}/users/{slot}/password - Update user password
	router.Handle(slot+"/password", r.requireScope(bmcAdminScope, r.handler.SetUserPassword)).Methods("PUT")

	// PUT /api/v1/bmc/{profileID}/users/{slot}/privilege - Update user privilege
	router.Handle(slot+"/privilege", r.requireScope(bmcAdminScope, r.handler.SetUserPrivilege)).Methods("PUT")
}
