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
	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
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

// RegisterRoutes registers all DNS REST routes on the provided router.
func (r *DNSRouter) RegisterRoutes(router *mux.Router) {
	// Create subrouter for DNS endpoints
	dnsRouter := router.PathPrefix(basePath).Subrouter()

	// Register all route groups
	r.registerZoneRoutes(dnsRouter)
	r.registerRecordRoutes(dnsRouter)
	r.registerResolutionRoutes(dnsRouter)
	r.registerDNSSECRoutes(dnsRouter)
	r.registerRegistrationRoutes(dnsRouter)
}

// registerZoneRoutes registers zone management endpoints
// POST   /api/v1/dns/zones           - Create zone
// GET    /api/v1/dns/zones           - List zones
// GET    /api/v1/dns/zones/{zone}    - Get zone
// PUT    /api/v1/dns/zones/{zone}    - Update zone
// DELETE /api/v1/dns/zones/{zone}    - Delete zone
func (r *DNSRouter) registerZoneRoutes(router *mux.Router) {
	// Zone collection routes
	router.HandleFunc("/zones", r.handlers.CreateZone).Methods("POST")
	router.HandleFunc("/zones", r.handlers.ListZones).Methods("GET")

	// Zone instance routes
	router.HandleFunc("/zones/{zone}", r.handlers.GetZone).Methods("GET")
	router.HandleFunc("/zones/{zone}", r.handlers.UpdateZone).Methods("PUT")
	router.HandleFunc("/zones/{zone}", r.handlers.DeleteZone).Methods("DELETE")
}

// registerRecordRoutes registers record management endpoints
// POST   /api/v1/dns/zones/{zone}/records              - Add record
// GET    /api/v1/dns/zones/{zone}/records              - List records
// GET    /api/v1/dns/zones/{zone}/records/{type}/{name} - Get record
// DELETE /api/v1/dns/zones/{zone}/records/{type}/{name} - Delete record
func (r *DNSRouter) registerRecordRoutes(router *mux.Router) {
	router.HandleFunc("/zones/{zone}/records", r.handlers.AddRecord).Methods("POST")
	router.HandleFunc("/zones/{zone}/records", r.handlers.ListRecords).Methods("GET")
	router.HandleFunc("/zones/{zone}/records/{type}/{name}", r.handlers.GetRecord).Methods("GET")
	router.HandleFunc("/zones/{zone}/records/{type}/{name}", r.handlers.DeleteRecord).Methods("DELETE")
}

// registerResolutionRoutes registers name resolution endpoints
// GET /api/v1/dns/resolve?fqdn={fqdn}&type={type} - Resolve from managed zones
func (r *DNSRouter) registerResolutionRoutes(router *mux.Router) {
	router.HandleFunc("/resolve", r.handlers.Resolve).Methods("GET")
}

// registerDNSSECRoutes registers DNSSEC management endpoints
// POST /api/v1/dns/zones/{zone}/sign   - Sign zone with DNSSEC
// GET  /api/v1/dns/zones/{zone}/dnssec - Get DNSSEC status
func (r *DNSRouter) registerDNSSECRoutes(router *mux.Router) {
	router.HandleFunc("/zones/{zone}/sign", r.handlers.SignZone).Methods("POST")
	router.HandleFunc("/zones/{zone}/dnssec", r.handlers.GetDNSSECStatus).Methods("GET")
}

// registerRegistrationRoutes registers DNS registration endpoints
// POST /api/v1/dns/register - Register FQDN with IP
func (r *DNSRouter) registerRegistrationRoutes(router *mux.Router) {
	router.HandleFunc("/register", r.handlers.Register).Methods("POST")
}
