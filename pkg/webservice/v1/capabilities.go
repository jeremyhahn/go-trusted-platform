// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// Capability kinds. A service entry gates a whole console page; a route
// entry gates one control.
const (
	CapabilityKindService = "service"
	CapabilityKindRoute   = "route"
)

// Reasons a capability is disabled. A dark service's reason is
// CapabilityReasonNotConfigured followed by the service name.
const (
	CapabilityReasonNotConfigured      = "not-configured: "
	CapabilityReasonUnimplemented      = "unimplemented"
	CapabilityReasonBlockedIntegration = "blocked: integration"
)

// capabilitiesPath is mounted under the versioned API prefix.
const capabilitiesPath = "/capabilities"

// Capability is one operation the server offers, or declines to.
type Capability struct {
	// Op is a service name for kind "service", and "METHOD /path/template"
	// for kind "route" (ANY for a route without a method matcher).
	Op      string `json:"op"`
	Kind    string `json:"kind"`
	Service string `json:"service,omitempty"`
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason,omitempty"`
}

// CapabilitiesResponse is the payload of GET /api/v1/capabilities.
type CapabilitiesResponse struct {
	Capabilities []Capability `json:"capabilities"`
	Total        int          `json:"total"`
	Enabled      int          `json:"enabled"`
}

// recordNewRoutes runs register and returns the routes it added to router,
// so a group of placeholder routes can be told apart from real ones by
// what was registered rather than by a hand-kept list.
func recordNewRoutes(router *mux.Router, register func()) map[*mux.Route]struct{} {
	before := map[*mux.Route]struct{}{}
	_ = router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		before[route] = struct{}{}
		return nil
	})
	register()
	added := map[*mux.Route]struct{}{}
	_ = router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if _, ok := before[route]; !ok {
			added[route] = struct{}{}
		}
		return nil
	})
	return added
}

// registerCapabilitiesEndpoint mounts GET /capabilities on router. The
// listing is built per request from the route table router has by then,
// the services the registry recorded, and the stub routes. middlewares,
// when given, guard the endpoint.
func registerCapabilitiesEndpoint(
	router *mux.Router,
	services *ServiceRegistry,
	stubs map[*mux.Route]struct{},
	writer response.HttpWriter,
	middlewares []mux.MiddlewareFunc,
) {
	host := router
	if len(middlewares) > 0 {
		host = router.NewRoute().Subrouter()
		host.Use(middlewares...)
	}
	route := host.NewRoute().Path(capabilitiesPath).Methods(http.MethodGet)
	base := ""
	if template, err := route.GetPathTemplate(); err == nil {
		base = strings.TrimSuffix(template, capabilitiesPath)
	}
	route.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if writer == nil {
			http.Error(w, "capabilities: response writer not configured",
				http.StatusInternalServerError)
			return
		}
		writer.Success200(w, req, buildCapabilities(router, base, services, stubs))
	})
}

// buildCapabilities lists every service the registry recorded and every
// method + path template in router's table.
func buildCapabilities(
	router *mux.Router,
	base string,
	services *ServiceRegistry,
	stubs map[*mux.Route]struct{},
) CapabilitiesResponse {
	var entries []*ServiceEntry
	if services != nil {
		entries = services.Snapshot()
	}

	caps := make([]Capability, 0, len(entries))
	for _, e := range entries {
		caps = append(caps, serviceCapability(e))
	}

	seen := map[string]bool{}
	var routes []Capability
	_ = router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if route.GetHandler() == nil {
			return nil
		}
		template, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			methods = []string{"ANY"}
		}
		owner := owningService(entries, base, template)
		_, stub := stubs[route]
		for _, method := range methods {
			op := method + " " + template
			// mux serves the first match, so the first registration wins.
			if seen[op] {
				continue
			}
			seen[op] = true
			c := Capability{Op: op, Kind: CapabilityKindRoute, Enabled: true}
			if owner != nil {
				c.Service = owner.Name
			}
			switch {
			case stub:
				c.Enabled, c.Reason = false, CapabilityReasonBlockedIntegration
			case owner != nil && !owner.Configured:
				c.Enabled, c.Reason = false, CapabilityReasonNotConfigured+owner.Name
			}
			routes = append(routes, c)
		}
		return nil
	})
	sort.Slice(routes, func(i, j int) bool { return routes[i].Op < routes[j].Op })
	caps = append(caps, routes...)

	enabled := 0
	for _, c := range caps {
		if c.Enabled {
			enabled++
		}
	}
	return CapabilitiesResponse{Capabilities: caps, Total: len(caps), Enabled: enabled}
}

func serviceCapability(e *ServiceEntry) Capability {
	c := Capability{Op: e.Name, Kind: CapabilityKindService, Service: e.Name, Enabled: e.Configured}
	if !e.Configured {
		c.Reason = CapabilityReasonNotConfigured + e.Name
	}
	return c
}

// owningService returns the service with the longest prefix covering
// template, or nil.
func owningService(entries []*ServiceEntry, base, template string) *ServiceEntry {
	var owner *ServiceEntry
	for _, e := range entries {
		if e.Prefix == "" {
			continue
		}
		prefix := base + e.Prefix
		if template != prefix && !strings.HasPrefix(template, prefix+"/") {
			continue
		}
		if owner == nil || len(e.Prefix) > len(owner.Prefix) {
			owner = e
		}
	}
	return owner
}

// authenticatedOnly admits any authenticated caller, whatever its roles,
// and refuses everyone when the authentication seam is unavailable.
func (v1Router *Router) authenticatedOnly() []mux.MiddlewareFunc {
	authenticate, guard, err := v1Router.authorization()
	if err != nil {
		v1Router.logger.Error(err, "the capabilities listing will deny every request")
		return []mux.MiddlewareFunc{v1Router.denyAll(err)}
	}
	return []mux.MiddlewareFunc{
		mux.MiddlewareFunc(authenticate),
		mux.MiddlewareFunc(guard.RequireAllRoles()),
	}
}
