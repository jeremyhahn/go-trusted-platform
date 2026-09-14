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

package sdn

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// NetworkZonePathSpec declares a directed egress path from one zone to
// another, optionally scoped to a service allowlist.
type NetworkZonePathSpec struct {
	Zone     string   `json:"zone"`
	Services []string `json:"services,omitempty"`
}

// NetworkZoneRequest is the REST body for creating or updating a
// network trust zone. On update the URL path {name} identifies the
// zone and a mismatched body name is rejected.
type NetworkZoneRequest struct {
	Name             string                `json:"name"`
	InternetIngress  bool                  `json:"internet_ingress,omitempty"`
	IsolateFrom      []string              `json:"isolate_from,omitempty"`
	AllowTo          []NetworkZonePathSpec `json:"allow_to,omitempty"`
	Services         []string              `json:"services,omitempty"`
	Isolate          bool                  `json:"isolate,omitempty"`
	IsolatePerTenant bool                  `json:"isolate_per_tenant,omitempty"`
	OOB              bool                  `json:"oob,omitempty"`
	LifecycleRole    string                `json:"lifecycle_role,omitempty"`
	Omit             bool                  `json:"omit,omitempty"`
}

// NetworkZoneResponse mirrors the daemon REST zone contract
// (pkg/api/rest) so the WebUI parses both surfaces identically.
type NetworkZoneResponse struct {
	Name             string                `json:"name"`
	InternetIngress  bool                  `json:"internet_ingress,omitempty"`
	IsolateFrom      []string              `json:"isolate_from,omitempty"`
	AllowTo          []NetworkZonePathSpec `json:"allow_to,omitempty"`
	Services         []string              `json:"services,omitempty"`
	Isolate          bool                  `json:"isolate,omitempty"`
	IsolatePerTenant bool                  `json:"isolate_per_tenant,omitempty"`
	OOB              bool                  `json:"oob,omitempty"`
	LifecycleRole    string                `json:"lifecycle_role,omitempty"`
	Omit             bool                  `json:"omit,omitempty"`
	RestartRequired  bool                  `json:"restart_required,omitempty"`
	CreatedAt        time.Time             `json:"created_at"`
	UpdatedAt        time.Time             `json:"updated_at"`
}

// NetworkZoneListResponse is the payload for listing network zones.
type NetworkZoneListResponse struct {
	Zones     []NetworkZoneResponse `json:"zones"`
	Count     int                   `json:"count"`
	Timestamp time.Time             `json:"timestamp"`
}

// NetworkZoneDeleteResponse is the payload for a zone deletion,
// matching the documented daemon REST shape
// (docs/sdn/api-reference-rest.md).
type NetworkZoneDeleteResponse struct {
	Deleted         bool `json:"deleted"`
	RestartRequired bool `json:"restart_required"`
}

// NetworkZoneAssignRequest is the REST body for assigning a network
// segment to a trust zone.
type NetworkZoneAssignRequest struct {
	Zone string `json:"zone"`
}

// NetworkZoneAssignResponse is the payload for a zone assignment,
// matching the documented daemon REST shape
// (docs/sdn/api-reference-rest.md).
type NetworkZoneAssignResponse struct {
	Success         bool `json:"success"`
	RestartRequired bool `json:"restart_required"`
}

// registerZoneRoutes registers network trust zone CRUD endpoints,
// closing the docs/13 G7 REST gap for zones on the webservice surface:
//
//	POST   /api/v1/sdn/zones                    - Create zone
//	GET    /api/v1/sdn/zones                    - List zones (?lifecycle_role=)
//	PUT    /api/v1/sdn/zones/{name}             - Update zone
//	DELETE /api/v1/sdn/zones/{name}             - Delete zone
//	PUT    /api/v1/sdn/networks/{network}/zone  - Assign network to zone
func (r *SDNRouter) registerZoneRoutes(router *mux.Router) {
	router.HandleFunc("/zones", r.handlers.CreateZone).Methods("POST")
	router.HandleFunc("/zones", r.handlers.ListZones).Methods("GET")
	router.HandleFunc("/zones/{name}", r.handlers.UpdateZone).Methods("PUT")
	router.HandleFunc("/zones/{name}", r.handlers.DeleteZone).Methods("DELETE")
	router.HandleFunc("/networks/{network}/zone", r.handlers.AssignZone).Methods("PUT")
}

// zoneRequestToProto converts a REST zone body to the proto config.
func zoneRequestToProto(req *NetworkZoneRequest) *platformv1.NetworkZoneConfig {
	allowTo := make([]*platformv1.NetworkZonePath, 0, len(req.AllowTo))
	for _, p := range req.AllowTo {
		allowTo = append(allowTo, &platformv1.NetworkZonePath{
			Zone:     p.Zone,
			Services: p.Services,
		})
	}
	return &platformv1.NetworkZoneConfig{
		Name:             req.Name,
		InternetIngress:  req.InternetIngress,
		IsolateFrom:      req.IsolateFrom,
		AllowTo:          allowTo,
		Services:         req.Services,
		Isolate:          req.Isolate,
		IsolatePerTenant: req.IsolatePerTenant,
		Oob:              req.OOB,
		LifecycleRole:    req.LifecycleRole,
		Omit:             req.Omit,
	}
}

// zoneProtoToResponse converts a proto zone record to the REST payload.
func zoneProtoToResponse(zone *platformv1.NetworkZone) NetworkZoneResponse {
	resp := NetworkZoneResponse{RestartRequired: zone.GetRestartRequired()}
	if cfg := zone.GetConfig(); cfg != nil {
		allowTo := make([]NetworkZonePathSpec, 0, len(cfg.GetAllowTo()))
		for _, p := range cfg.GetAllowTo() {
			allowTo = append(allowTo, NetworkZonePathSpec{
				Zone:     p.GetZone(),
				Services: p.GetServices(),
			})
		}
		resp.Name = cfg.GetName()
		resp.InternetIngress = cfg.GetInternetIngress()
		resp.IsolateFrom = cfg.GetIsolateFrom()
		resp.AllowTo = allowTo
		resp.Services = cfg.GetServices()
		resp.Isolate = cfg.GetIsolate()
		resp.IsolatePerTenant = cfg.GetIsolatePerTenant()
		resp.OOB = cfg.GetOob()
		resp.LifecycleRole = cfg.GetLifecycleRole()
		resp.Omit = cfg.GetOmit()
	}
	if ts := zone.GetCreatedAt(); ts != nil {
		resp.CreatedAt = ts.AsTime()
	}
	if ts := zone.GetUpdatedAt(); ts != nil {
		resp.UpdatedAt = ts.AsTime()
	}
	return resp
}

// CreateZone handles POST /api/v1/sdn/zones
func (h *SDNHandlers) CreateZone(w http.ResponseWriter, r *http.Request) {
	var req NetworkZoneRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}
	if req.Name == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.sdnService.CreateNetworkZone(ctx, &platformv1.CreateNetworkZoneRequest{
		Config: zoneRequestToProto(&req),
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}

	h.respWriter.Success201(w, r, zoneProtoToResponse(resp.GetZone()))
}

// ListZones handles GET /api/v1/sdn/zones
func (h *SDNHandlers) ListZones(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.sdnService.ListNetworkZones(ctx, &platformv1.ListNetworkZonesRequest{
		LifecycleRole: r.URL.Query().Get("lifecycle_role"),
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}

	zones := make([]NetworkZoneResponse, 0, len(resp.GetZones()))
	for _, z := range resp.GetZones() {
		zones = append(zones, zoneProtoToResponse(z))
	}

	h.respWriter.Success200(w, r, NetworkZoneListResponse{
		Zones:     zones,
		Count:     len(zones),
		Timestamp: time.Now().UTC(),
	})
}

// UpdateZone handles PUT /api/v1/sdn/zones/{name}
func (h *SDNHandlers) UpdateZone(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if name == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	var req NetworkZoneRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}
	// The URL path identifies the zone; the body name is optional but
	// must match when present.
	if req.Name != "" && req.Name != name {
		h.respWriter.Error400(w, r, ErrZoneNameMismatch{Path: name, Body: req.Name})
		return
	}
	req.Name = name

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.sdnService.UpdateNetworkZone(ctx, &platformv1.UpdateNetworkZoneRequest{
		Name:   name,
		Config: zoneRequestToProto(&req),
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}

	h.respWriter.Success200(w, r, zoneProtoToResponse(resp.GetZone()))
}

// AssignZone handles PUT /api/v1/sdn/networks/{network}/zone
func (h *SDNHandlers) AssignZone(w http.ResponseWriter, r *http.Request) {
	network := mux.Vars(r)["network"]

	var req NetworkZoneAssignRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}
	if req.Zone == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.sdnService.AssignNetworkZone(ctx, &platformv1.AssignNetworkZoneRequest{
		Network: network,
		Zone:    req.Zone,
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}

	h.respWriter.Success200(w, r, NetworkZoneAssignResponse{
		Success:         true,
		RestartRequired: resp.GetRestartRequired(),
	})
}

// DeleteZone handles DELETE /api/v1/sdn/zones/{name}
func (h *SDNHandlers) DeleteZone(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if name == "" {
		h.respWriter.Error400(w, r, ErrMissingZoneName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	resp, err := h.sdnService.DeleteNetworkZone(ctx, &platformv1.DeleteNetworkZoneRequest{
		Name: name,
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}

	h.respWriter.Success200(w, r, NetworkZoneDeleteResponse{
		Deleted:         true,
		RestartRequired: resp.GetRestartRequired(),
	})
}
