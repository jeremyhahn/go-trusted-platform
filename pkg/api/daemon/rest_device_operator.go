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
	"log/slog"
	"net/http"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	restdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The scopes the device operator routes take: each is the scope its gRPC
// twin takes in pkg/api/grpc/method_permissions.go, as on the webservice
// (pkg/webservice/v1/router/device.go).
const (
	deviceReadScope   = "device:read"
	deviceWriteScope  = "device:write"
	deviceDeleteScope = "device:delete"
)

// DeviceOperatorServices are the services behind the daemon's device
// operator routes: the device, profile and template services the gRPC,
// QUIC, MCP and Unix-socket transports share, and the daemon's device gRPC
// server, which owns Enable/Disable and attestation-certificate recording.
// Every field is optional; a route whose service is nil is not mounted.
type DeviceOperatorServices struct {
	Devices   device.DeviceService
	Profiles  device.DeviceProfileService
	Templates device.DeviceTemplateService
	Server    platformv1.DeviceServiceServer
}

// deviceOperatorRoute is one guarded device operator route.
type deviceOperatorRoute struct {
	method  string
	path    string
	scope   string
	handler http.HandlerFunc
}

// SetDeviceOperatorHandlers mounts the device operator routes the SDK REST
// adapter claims and pkg/api/rest's device routes do not serve: the device
// count, Enable/Disable, attestation-certificate recording, the profile
// routes under /api/v1/device/profiles (CRUD, count, match, the MAC and
// serial lookups, find-config, assign and unassign), activate-json and the
// template routes. The handlers are the webservice's
// (pkg/webservice/v1/device), so both listeners speak the same domain JSON
// in the same {code, success, payload} envelope, and every route runs behind
// guard with its gRPC twin's scope. A nil guard answers 403.
//
// Call it before SetDeviceHandlers: pkg/api/rest serves GET
// /api/v1/devices/{id} with an unconstrained id, and the router answers
// with the first route that matches, so /api/v1/devices/count must be
// registered first.
func (s *RESTServer) SetDeviceOperatorHandlers(services DeviceOperatorServices, guard *restapi.ScopeGuard) {
	routes := deviceOperatorRoutes(s.logger, services)
	if len(routes) == 0 {
		return
	}
	for _, route := range routes {
		s.router.HandleFunc(restBasePath+route.path, guard.Require(route.scope, route.handler)).Methods(route.method)
	}
	s.logger.Info("Device operator REST routes registered", "routes", len(routes))
}

// deviceOperatorRoutes builds the route table for the services present.
func deviceOperatorRoutes(logger *slog.Logger, services DeviceOperatorServices) []deviceOperatorRoute {
	log := logging.NewFromSlog(logger)
	writer := response.NewResponseWriter(log, nil)

	var routes []deviceOperatorRoute
	if services.Devices != nil || services.Profiles != nil {
		crud := restdevice.NewCRUDHandler(log, writer, services.Devices, services.Profiles)
		if services.Devices != nil {
			routes = append(routes, deviceOperatorRoute{http.MethodGet, "/devices/count", deviceReadScope, crud.CountDevices})
		}
		if services.Profiles != nil {
			routes = append(routes,
				deviceOperatorRoute{http.MethodPost, "/device/profiles", deviceWriteScope, crud.CreateProfile},
				deviceOperatorRoute{http.MethodGet, "/device/profiles", deviceReadScope, crud.ListProfiles},
				deviceOperatorRoute{http.MethodGet, "/device/profiles/count", deviceReadScope, crud.CountProfiles},
				deviceOperatorRoute{http.MethodPost, "/device/profiles/match", deviceReadScope, crud.FindMatchingProfile},
				deviceOperatorRoute{http.MethodGet, "/device/profiles/serial/{serial}", deviceReadScope, crud.FindProfileBySerial},
				deviceOperatorRoute{http.MethodGet, "/device/profiles/mac/{mac}", deviceReadScope, crud.FindProfileByMAC},
				deviceOperatorRoute{http.MethodGet, "/device/profiles/{id:[0-9]+}", deviceReadScope, crud.GetProfileByID},
				deviceOperatorRoute{http.MethodPut, "/device/profiles/{id:[0-9]+}", deviceWriteScope, crud.UpdateProfile},
				deviceOperatorRoute{http.MethodDelete, "/device/profiles/{id:[0-9]+}", deviceDeleteScope, crud.DeleteProfile},
			)
		}
		if services.Devices != nil && services.Profiles != nil {
			routes = append(routes, deviceOperatorRoute{http.MethodPost, "/device/activate-json", deviceWriteScope, crud.ActivateDevice})
		}
	}
	if services.Templates != nil && services.Profiles != nil && services.Devices != nil {
		templates := restdevice.NewTemplateHandler(log, writer, services.Templates, services.Profiles, services.Devices)
		routes = append(routes,
			deviceOperatorRoute{http.MethodPost, "/device/templates", deviceWriteScope, templates.CreateTemplate},
			deviceOperatorRoute{http.MethodGet, "/device/templates", deviceReadScope, templates.ListTemplates},
			deviceOperatorRoute{http.MethodGet, "/device/templates/name/{name}", deviceReadScope, templates.FindTemplateByName},
			deviceOperatorRoute{http.MethodGet, "/device/templates/{id:[0-9]+}", deviceReadScope, templates.GetTemplate},
			deviceOperatorRoute{http.MethodPut, "/device/templates/{id:[0-9]+}", deviceWriteScope, templates.UpdateTemplate},
			deviceOperatorRoute{http.MethodDelete, "/device/templates/{id:[0-9]+}", deviceDeleteScope, templates.DeleteTemplate},
			deviceOperatorRoute{http.MethodPost, "/device/templates/{id:[0-9]+}/create-profile", deviceWriteScope, templates.CreateProfileFromTemplate},
			deviceOperatorRoute{http.MethodGet, "/device/profiles/find-config", deviceReadScope, templates.FindConfigForDevice},
			deviceOperatorRoute{http.MethodPost, "/device/profiles/{id:[0-9]+}/assign", deviceWriteScope, templates.AssignProfileToDevice},
			deviceOperatorRoute{http.MethodPost, "/device/profiles/{id:[0-9]+}/unassign", deviceWriteScope, templates.UnassignProfileFromDevice},
		)
	}
	if lifecycle := restdevice.NewLifecycleHandler(log, writer, services.Server); lifecycle != nil {
		routes = append(routes,
			deviceOperatorRoute{http.MethodPost, "/devices/{id:[0-9]+}/disable", deviceWriteScope, lifecycle.HandleDisable},
			deviceOperatorRoute{http.MethodPost, "/devices/{id:[0-9]+}/enable", deviceWriteScope, lifecycle.HandleEnable},
		)
	}
	if recorder := restdevice.NewAttestCertHandler(log, writer, services.Server); recorder != nil {
		routes = append(routes, deviceOperatorRoute{http.MethodPost, "/devices/{id:[0-9]+}/attest-cert/record", deviceWriteScope, recorder.HandleRecordAttestCert})
	}
	return routes
}
