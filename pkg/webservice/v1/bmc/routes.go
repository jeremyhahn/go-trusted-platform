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

package bmc

import (
	"net/http"

	"github.com/gorilla/mux"
)

// RouteGuard wraps a BMC route's handler with the check its scope names.
// The web console passes the platform token's scope check; the daemon REST
// listener, which authenticates by mTLS only, passes PassThroughGuard.
type RouteGuard interface {
	Require(scope string, next http.HandlerFunc) http.HandlerFunc
}

// The BMC scopes, as the MCP tools and the gRPC service check them.
const (
	ScopeRead  = "bmc:read"
	ScopePower = "bmc:power"
	ScopeWrite = "bmc:write"
	ScopeMedia = "bmc:media"
	ScopeAdmin = "bmc:admin"
)

// PassThroughGuard checks no scope. The daemon REST listener uses it: its
// callers are authenticated by the mTLS handshake, which carries no scopes.
type PassThroughGuard struct{}

// Require returns next unchanged.
func (PassThroughGuard) Require(_ string, next http.HandlerFunc) http.HandlerFunc {
	return next
}

// RegisterRoutes mounts the twenty BMC routes on api (a router whose paths
// are relative to /api/v1), each behind guard with its scope: reads under
// bmc:read, power actions under bmc:power, the boot device under bmc:write,
// virtual media under bmc:media, and provisioning, certificates, enrolment
// and users under bmc:admin. The web console and the daemon REST listener
// share this one table.
func RegisterRoutes(api *mux.Router, h RestHandler, guard RouteGuard) {
	route := func(path, method, scope string, fn http.HandlerFunc) {
		api.HandleFunc(path, guard.Require(scope, fn)).Methods(method)
	}
	const profile = "/bmc/{profileID:[0-9]+}"
	route(profile+"/power", http.MethodPost, ScopePower, h.PowerAction)
	route(profile+"/power", http.MethodGet, ScopeRead, h.PowerStatus)
	route(profile+"/boot-device", http.MethodPost, ScopeWrite, h.SetBootDevice)
	route(profile+"/boot-device", http.MethodGet, ScopeRead, h.GetBootDevice)
	route(profile+"/virtual-media", http.MethodPost, ScopeMedia, h.MountISO)
	route(profile+"/virtual-media", http.MethodDelete, ScopeMedia, h.UnmountISO)
	route(profile+"/virtual-media", http.MethodGet, ScopeRead, h.VirtualMediaStatus)
	route(profile+"/sensors", http.MethodGet, ScopeRead, h.GetSensors)
	route(profile+"/system-info", http.MethodGet, ScopeRead, h.GetSystemInfo)
	route(profile+"/provision", http.MethodPost, ScopeAdmin, h.Provision)
	route(profile+"/provision", http.MethodGet, ScopeRead, h.ProvisionStatus)
	route(profile+"/enroll", http.MethodPost, ScopeAdmin, h.EnrollBMC)
	route(profile+"/cert/restore", http.MethodPost, ScopeAdmin, h.RestoreBMC)
	route(profile+"/cert", http.MethodGet, ScopeRead, h.GetWebCertificate)
	route(profile+"/cert", http.MethodPut, ScopeAdmin, h.ReplaceWebCertificate)
	route(profile+"/users", http.MethodGet, ScopeRead, h.ListUsers)
	route(profile+"/users", http.MethodPost, ScopeAdmin, h.CreateUser)
	route(profile+"/users/{slot:[0-9]+}", http.MethodDelete, ScopeAdmin, h.DeleteUser)
	route(profile+"/users/{slot:[0-9]+}/password", http.MethodPut, ScopeAdmin, h.SetUserPassword)
	route(profile+"/users/{slot:[0-9]+}/privilege", http.MethodPut, ScopeAdmin, h.SetUserPrivilege)
}
