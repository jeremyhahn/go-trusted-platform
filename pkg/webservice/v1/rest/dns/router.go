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

package dns

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	basePath = "/dns"
)

// DNSRouter provides REST routing for DNS operations.
// All handlers delegate to the dns.DNSService interface (service layer).
type DNSRouter struct {
	handlers *DNSHandlers
	router.WebServiceRouter
}

// NewDNSRouter creates a new DNSRouter instance.
func NewDNSRouter(
	logger *logging.Logger,
	service dns.DNSService,
	respWriter response.HttpWriter,
) *DNSRouter {
	return &DNSRouter{
		handlers: NewDNSHandlers(logger, service, respWriter),
	}
}

// Route is one DNS REST route: its method, its path under the /dns base,
// the DNSService RPC whose scope guards it, and the handler that binds it.
// A server that mounts the routes behind scope checks (platformd's REST
// listener) takes the scope from RPC, so REST and gRPC require the same one.
type Route struct {
	Method  string
	Path    string
	RPC     string
	Handler http.HandlerFunc
}

// BasePath is the path every DNS route is mounted under, relative to the
// /api/v1 router.
const BasePath = basePath

// Routes returns the DNS REST routes of docs/dns/api.md §2.
//
// Get record has no RPC: DNSService declares no GetRecord. It reads the
// zone's records as ListRecords does, so it carries ListRecords' scope, as
// the MCP dns_record_get tool does (docs/dns/api.md §3).
func (r *DNSRouter) Routes() []Route {
	h := r.handlers
	return []Route{
		// Zones
		{http.MethodPost, "/zones", platformv1.DNSService_CreateZone_FullMethodName, h.CreateZone},
		{http.MethodGet, "/zones", platformv1.DNSService_ListZones_FullMethodName, h.ListZones},
		{http.MethodGet, "/zones/{zone}", platformv1.DNSService_GetZone_FullMethodName, h.GetZone},
		{http.MethodPut, "/zones/{zone}", platformv1.DNSService_UpdateZone_FullMethodName, h.UpdateZone},
		{http.MethodDelete, "/zones/{zone}", platformv1.DNSService_DeleteZone_FullMethodName, h.DeleteZone},

		// Records
		{http.MethodPost, "/zones/{zone}/records", platformv1.DNSService_AddRecord_FullMethodName, h.AddRecord},
		{http.MethodGet, "/zones/{zone}/records", platformv1.DNSService_ListRecords_FullMethodName, h.ListRecords},
		{http.MethodGet, "/zones/{zone}/records/{type}/{name}", platformv1.DNSService_ListRecords_FullMethodName, h.GetRecord},
		{http.MethodDelete, "/zones/{zone}/records/{type}/{name}", platformv1.DNSService_DeleteRecord_FullMethodName, h.DeleteRecord},

		// Resolution from managed zones
		{http.MethodGet, "/resolve", platformv1.DNSService_Resolve_FullMethodName, h.Resolve},

		// DNSSEC
		{http.MethodPost, "/zones/{zone}/sign", platformv1.DNSService_SignZone_FullMethodName, h.SignZone},
		{http.MethodGet, "/zones/{zone}/dnssec", platformv1.DNSService_GetDNSSECStatus_FullMethodName, h.GetDNSSECStatus},

		// Registration
		{http.MethodPost, "/register", platformv1.DNSService_Register_FullMethodName, h.Register},
	}
}

// RegisterRoutes registers all DNS REST routes on the provided router. The
// webservice gates /api/v1/dns/** on the admin role in its middleware, so
// the routes are mounted without a per-route scope check here.
func (r *DNSRouter) RegisterRoutes(router *mux.Router) {
	dnsRouter := router.PathPrefix(basePath).Subrouter()
	for _, route := range r.Routes() {
		dnsRouter.HandleFunc(route.Path, route.Handler).Methods(route.Method)
	}
}
