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

// NetworkZonePrivilegedAccess is the audited override a zone carries when
// it opens a path into control-plane or management beyond the reference
// defaults.
type NetworkZonePrivilegedAccess struct {
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
}

// NetworkZoneRequest is the REST body for creating an owner-defined zone or
// updating a zone. On update the URL path {name} identifies the zone and a
// mismatched body name is rejected.
type NetworkZoneRequest struct {
	Name             string                       `json:"name,omitempty"`
	Offset           uint8                        `json:"offset,omitempty"`
	PortClasses      []string                     `json:"port_classes,omitempty"`
	InternetIngress  bool                         `json:"internet_ingress,omitempty"`
	IsolateFrom      []string                     `json:"isolate_from,omitempty"`
	AllowTo          []NetworkZonePathSpec        `json:"allow_to,omitempty"`
	Services         []string                     `json:"services,omitempty"`
	Isolate          bool                         `json:"isolate,omitempty"`
	OOB              bool                         `json:"oob,omitempty"`
	LifecycleRole    string                       `json:"lifecycle_role,omitempty"`
	PrivilegedAccess *NetworkZonePrivilegedAccess `json:"privileged_access,omitempty"`
}

// NetworkZoneNumbering is a zone's numbering derived by the network plan.
type NetworkZoneNumbering struct {
	VLAN    uint16 `json:"vlan"`
	Subnet4 string `json:"subnet4"`
	Subnet6 string `json:"subnet6,omitempty"`
	Gateway string `json:"gateway"`
}

// NetworkZoneResponse mirrors the daemon REST zone contract
// (pkg/sdn/gateway.ZoneView) so the WebUI parses both surfaces
// identically.
type NetworkZoneResponse struct {
	NetworkZoneRequest
	Numbering       *NetworkZoneNumbering `json:"numbering,omitempty"`
	RestartRequired bool                  `json:"restart_required,omitempty"`
	CreatedAt       time.Time             `json:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
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

// registerZoneRoutes registers network trust zone CRUD endpoints,
// closing the docs/13 G7 REST gap for zones on the webservice surface:
//
//	POST   /api/v1/sdn/zones                    - Create zone
//	GET    /api/v1/sdn/zones                    - List zones (?lifecycle_role=)
//	PUT    /api/v1/sdn/zones/{name}             - Update zone
//	DELETE /api/v1/sdn/zones/{name}             - Delete zone
func (r *SDNRouter) registerZoneRoutes(router *mux.Router) {
	router.HandleFunc("/zones", r.handlers.CreateZone).Methods("POST")
	router.HandleFunc("/zones", r.handlers.ListZones).Methods("GET")
	router.HandleFunc("/zones/{name}", r.handlers.UpdateZone).Methods("PUT")
	router.HandleFunc("/zones/{name}", r.handlers.DeleteZone).Methods("DELETE")
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
	cfg := &platformv1.NetworkZoneConfig{
		Name:            req.Name,
		Offset:          uint32(req.Offset),
		PortClasses:     req.PortClasses,
		InternetIngress: req.InternetIngress,
		IsolateFrom:     req.IsolateFrom,
		AllowTo:         allowTo,
		Services:        req.Services,
		Isolate:         req.Isolate,
		Oob:             req.OOB,
		LifecycleRole:   req.LifecycleRole,
	}
	if pa := req.PrivilegedAccess; pa != nil {
		cfg.PrivilegedAccess = &platformv1.NetworkZonePrivilegedAccess{
			Reason:     pa.Reason,
			ApprovedBy: pa.ApprovedBy,
		}
	}
	return cfg
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
		resp.Offset = uint8(cfg.GetOffset())
		resp.PortClasses = cfg.GetPortClasses()
		resp.InternetIngress = cfg.GetInternetIngress()
		resp.IsolateFrom = cfg.GetIsolateFrom()
		resp.AllowTo = allowTo
		resp.Services = cfg.GetServices()
		resp.Isolate = cfg.GetIsolate()
		resp.OOB = cfg.GetOob()
		resp.LifecycleRole = cfg.GetLifecycleRole()
		if pa := cfg.GetPrivilegedAccess(); pa != nil {
			resp.PrivilegedAccess = &NetworkZonePrivilegedAccess{
				Reason:     pa.GetReason(),
				ApprovedBy: pa.GetApprovedBy(),
			}
		}
	}
	if n := zone.GetNumbering(); n != nil {
		resp.Numbering = &NetworkZoneNumbering{
			VLAN:    uint16(n.GetVlan()),
			Subnet4: n.GetSubnet4(),
			Subnet6: n.GetSubnet6(),
			Gateway: n.GetGateway(),
		}
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
