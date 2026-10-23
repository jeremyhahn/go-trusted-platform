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

package gateway

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ipamBasePath mounts the IPAM CRUD surface under the SDN prefix. The
// path shape follows the documented contract in
// docs/sdn/ipam/api-reference-rest.md (the daemon REST stack serves the
// same paths), so the WebUI works against either surface.
const ipamBasePath = "/sdn/gateway/ipam"

// IPAMPoolRequest is the REST body for creating or updating a pool.
// The JSON contract is snake_case to match the documented surface —
// protorest/protojson is deliberately not used here.
type IPAMPoolRequest struct {
	ID                     string `json:"id,omitempty"`
	Name                   string `json:"name,omitempty"`
	CIDR                   string `json:"cidr,omitempty"`
	Gateway                string `json:"gateway,omitempty"`
	Zone                   string `json:"zone,omitempty"`
	Description            string `json:"description,omitempty"`
	DefaultLeaseDurationNs int64  `json:"default_lease_duration_nanos,omitempty"`
	InactivityTimeoutNs    int64  `json:"inactivity_timeout_nanos,omitempty"`
	// Reserved lists never-allocatable prefixes. On update, an omitted
	// field keeps the pool's list and an empty list clears it.
	Reserved []string `json:"reserved,omitempty"`
	// RangeStart and RangeEnd bound dynamic allocation. On update, an
	// omitted field keeps the pool's bound and "" clears it.
	RangeStart *string `json:"range_start,omitempty"`
	RangeEnd   *string `json:"range_end,omitempty"`
}

// IPAMPoolResponse mirrors the daemon REST pool contract
// (pkg/api/rest/gateway_handlers.go) so both surfaces parse identically.
type IPAMPoolResponse struct {
	ID                     string     `json:"id"`
	Name                   string     `json:"name"`
	CIDR                   string     `json:"cidr"`
	Gateway                string     `json:"gateway,omitempty"`
	Zone                   string     `json:"zone,omitempty"`
	Description            string     `json:"description,omitempty"`
	Total                  uint64     `json:"total"`
	Allocated              uint64     `json:"allocated"`
	Available              uint64     `json:"available"`
	DefaultLeaseDurationNs int64      `json:"default_lease_duration_nanos,omitempty"`
	InactivityTimeoutNs    int64      `json:"inactivity_timeout_nanos,omitempty"`
	Reserved               []string   `json:"reserved,omitempty"`
	RangeStart             string     `json:"range_start,omitempty"`
	RangeEnd               string     `json:"range_end,omitempty"`
	CreatedAt              *time.Time `json:"created_at,omitempty"`
	UpdatedAt              *time.Time `json:"updated_at,omitempty"`
}

// IPAMPoolListResponse is the payload for listing pools.
type IPAMPoolListResponse struct {
	Pools     []IPAMPoolResponse `json:"pools"`
	Count     int                `json:"count"`
	Timestamp time.Time          `json:"timestamp"`
}

// IPAMAllocateRequest is the REST body for allocating an IP.
type IPAMAllocateRequest struct {
	PoolID   string `json:"pool_id"`
	DeviceID string `json:"device_id,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// IPAllocationResponse mirrors the daemon REST allocation contract.
type IPAllocationResponse struct {
	IP          string     `json:"ip"`
	PoolID      string     `json:"pool_id"`
	DeviceID    string     `json:"device_id,omitempty"`
	Hostname    string     `json:"hostname,omitempty"`
	Status      string     `json:"status"`
	AllocatedAt *time.Time `json:"allocated_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// IPAllocationListResponse is the payload for listing allocations.
type IPAllocationListResponse struct {
	Allocations []IPAllocationResponse `json:"allocations"`
	Count       int                    `json:"count"`
	Timestamp   time.Time              `json:"timestamp"`
}

// IPAMActionResponse is the body the pool-delete and allocation-release
// endpoints return. It mirrors the daemon REST stack's
// GatewayActionResponse (pkg/api/rest/gateway_handlers.go) field for
// field, because both references document the two stacks as serving the
// same object shapes: a client written against that contract has to be
// able to read either surface's answer with one type.
type IPAMActionResponse struct {
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	Action       string `json:"action"`
	Success      bool   `json:"success"`
	Message      string `json:"message,omitempty"`
}

// IPAMRouter wires the /api/v1/sdn/gateway/ipam CRUD surface onto the
// in-process GatewayServiceServer. It is distinct from GatewayRouter
// (basePath /gateway): this surface carries the full pool CRUD the
// WebUI's Networking → IPAM page manages, while /gateway/ipam keeps
// the reduced read-oriented set documented in docs/gateway/api.md.
type IPAMRouter struct {
	logger     *logging.Logger
	server     platformv1.GatewayServiceServer
	respWriter response.HttpWriter
	router.WebServiceRouter
}

// NewIPAMRouter creates an IPAM CRUD router.
func NewIPAMRouter(
	logger *logging.Logger,
	server platformv1.GatewayServiceServer,
	respWriter response.HttpWriter,
) *IPAMRouter {
	return &IPAMRouter{logger: logger, server: server, respWriter: respWriter}
}

// RegisterRoutes mounts the IPAM CRUD routes.
//
//	POST   /api/v1/sdn/gateway/ipam/pools             - CreateIPAMPool
//	GET    /api/v1/sdn/gateway/ipam/pools             - ListIPAMPools (?zone=)
//	GET    /api/v1/sdn/gateway/ipam/pools/{id}        - GetIPAMPool
//	PUT    /api/v1/sdn/gateway/ipam/pools/{id}        - UpdateIPAMPool
//	DELETE /api/v1/sdn/gateway/ipam/pools/{id}        - DeleteIPAMPool
//	POST   /api/v1/sdn/gateway/ipam/allocations       - AllocateIP
//	GET    /api/v1/sdn/gateway/ipam/allocations       - ListAllocations (?pool_id=)
//	DELETE /api/v1/sdn/gateway/ipam/allocations/{ip}  - ReleaseIP
func (r *IPAMRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(ipamBasePath).Subrouter()
	sr.HandleFunc("/pools", r.createPool).Methods("POST")
	sr.HandleFunc("/pools", r.listPools).Methods("GET")
	sr.HandleFunc("/pools/{id}", r.getPool).Methods("GET")
	sr.HandleFunc("/pools/{id}", r.updatePool).Methods("PUT")
	sr.HandleFunc("/pools/{id}", r.deletePool).Methods("DELETE")
	sr.HandleFunc("/allocations", r.allocate).Methods("POST")
	sr.HandleFunc("/allocations", r.listAllocations).Methods("GET")
	sr.HandleFunc("/allocations/{ip}", r.release).Methods("DELETE")
}

func (r *IPAMRouter) ensure(w http.ResponseWriter, req *http.Request) bool {
	if r.server == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "gateway"})
		return false
	}
	return true
}

func poolProtoToResponse(pool *platformv1.IPAMPool) IPAMPoolResponse {
	resp := IPAMPoolResponse{
		ID:                     pool.GetId(),
		Name:                   pool.GetName(),
		CIDR:                   pool.GetCidr(),
		Gateway:                pool.GetGateway(),
		Zone:                   pool.GetZone(),
		Description:            pool.GetDescription(),
		Total:                  pool.GetTotal(),
		Allocated:              pool.GetAllocated(),
		Available:              pool.GetAvailable(),
		DefaultLeaseDurationNs: pool.GetDefaultLeaseDurationNanos(),
		InactivityTimeoutNs:    pool.GetInactivityTimeoutNanos(),
		Reserved:               pool.GetReserved(),
		RangeStart:             pool.GetRangeStart(),
		RangeEnd:               pool.GetRangeEnd(),
	}
	if ts := pool.GetCreatedAt(); ts != nil {
		t := ts.AsTime()
		resp.CreatedAt = &t
	}
	if ts := pool.GetUpdatedAt(); ts != nil {
		t := ts.AsTime()
		resp.UpdatedAt = &t
	}
	return resp
}

func allocationProtoToResponse(alloc *platformv1.IPAllocation) IPAllocationResponse {
	resp := IPAllocationResponse{
		IP:       alloc.GetIp(),
		PoolID:   alloc.GetPoolId(),
		DeviceID: alloc.GetDeviceId(),
		Hostname: alloc.GetHostname(),
		Status:   alloc.GetStatus(),
	}
	if ts := alloc.GetAllocatedAt(); ts != nil {
		t := ts.AsTime()
		resp.AllocatedAt = &t
	}
	if ts := alloc.GetExpiresAt(); ts != nil {
		t := ts.AsTime()
		resp.ExpiresAt = &t
	}
	return resp
}

func (r *IPAMRouter) decode(w http.ResponseWriter, req *http.Request, v any) bool {
	if err := json.NewDecoder(req.Body).Decode(v); err != nil {
		r.respWriter.Error400(w, req, &protorest.ErrInvalidJSON{Cause: err})
		return false
	}
	return true
}

func (r *IPAMRouter) createPool(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	var body IPAMPoolRequest
	if !r.decode(w, req, &body) {
		return
	}
	resp, err := r.server.CreateIPAMPool(req.Context(), &platformv1.CreateIPAMPoolRequest{
		Id:                        body.ID,
		Name:                      body.Name,
		Cidr:                      body.CIDR,
		Gateway:                   body.Gateway,
		Zone:                      body.Zone,
		Description:               body.Description,
		DefaultLeaseDurationNanos: body.DefaultLeaseDurationNs,
		InactivityTimeoutNanos:    body.InactivityTimeoutNs,
		Reserved:                  body.Reserved,
		RangeStart:                derefString(body.RangeStart),
		RangeEnd:                  derefString(body.RangeEnd),
	})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	r.respWriter.Success201(w, req, poolProtoToResponse(resp.GetPool()))
}

func (r *IPAMRouter) listPools(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListIPAMPools(req.Context(), &platformv1.ListIPAMPoolsRequest{
		Zone: req.URL.Query().Get("zone"),
	})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	pools := make([]IPAMPoolResponse, 0, len(resp.GetPools()))
	for _, p := range resp.GetPools() {
		pools = append(pools, poolProtoToResponse(p))
	}
	r.respWriter.Success200(w, req, IPAMPoolListResponse{
		Pools:     pools,
		Count:     len(pools),
		Timestamp: time.Now().UTC(),
	})
}

func (r *IPAMRouter) getPool(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetIPAMPool(req.Context(), &platformv1.GetIPAMPoolRequest{
		Id: mux.Vars(req)["id"],
	})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	r.respWriter.Success200(w, req, poolProtoToResponse(resp.GetPool()))
}

func (r *IPAMRouter) updatePool(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	var body IPAMPoolRequest
	if !r.decode(w, req, &body) {
		return
	}
	id := mux.Vars(req)["id"]

	// Partial-update semantics per the documented contract: omitted
	// fields preserve the pool's current values. The gRPC
	// UpdateIPAMPool applies zone/description/lease/inactivity
	// unconditionally, so forwarding the REST body's zero values would
	// silently clear them — merge from the current pool first.
	current, err := r.server.GetIPAMPool(req.Context(), &platformv1.GetIPAMPoolRequest{Id: id})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	pool := current.GetPool()

	update := &platformv1.UpdateIPAMPoolRequest{
		Id:                        id,
		Name:                      pool.GetName(),
		Gateway:                   pool.GetGateway(),
		Zone:                      pool.GetZone(),
		Description:               pool.GetDescription(),
		DefaultLeaseDurationNanos: pool.GetDefaultLeaseDurationNanos(),
		InactivityTimeoutNanos:    pool.GetInactivityTimeoutNanos(),
	}
	if body.Name != "" {
		update.Name = body.Name
	}
	if body.Gateway != "" {
		update.Gateway = body.Gateway
	}
	if body.Zone != "" {
		update.Zone = body.Zone
	}
	if body.Description != "" {
		update.Description = body.Description
	}
	if body.DefaultLeaseDurationNs > 0 {
		update.DefaultLeaseDurationNanos = body.DefaultLeaseDurationNs
	}
	if body.InactivityTimeoutNs > 0 {
		update.InactivityTimeoutNanos = body.InactivityTimeoutNs
	}
	if body.Reserved != nil || body.RangeStart != nil || body.RangeEnd != nil {
		// Any window field present replaces the window; the others keep
		// the pool's current values.
		update.UpdateWindow = true
		update.Reserved = pool.GetReserved()
		update.RangeStart = pool.GetRangeStart()
		update.RangeEnd = pool.GetRangeEnd()
		if body.Reserved != nil {
			update.Reserved = body.Reserved
		}
		if body.RangeStart != nil {
			update.RangeStart = *body.RangeStart
		}
		if body.RangeEnd != nil {
			update.RangeEnd = *body.RangeEnd
		}
	}

	resp, err := r.server.UpdateIPAMPool(req.Context(), update)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	r.respWriter.Success200(w, req, poolProtoToResponse(resp.GetPool()))
}

func (r *IPAMRouter) deletePool(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	id := mux.Vars(req)["id"]
	if _, err := r.server.DeleteIPAMPool(req.Context(), &platformv1.DeleteIPAMPoolRequest{
		Id: id,
	}); err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	r.respWriter.Success200(w, req, IPAMActionResponse{
		ResourceID:   id,
		ResourceType: "ipam_pool",
		Action:       "delete",
		Success:      true,
		Message:      "pool deleted successfully",
	})
}

func (r *IPAMRouter) allocate(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	var body IPAMAllocateRequest
	if !r.decode(w, req, &body) {
		return
	}
	resp, err := r.server.AllocateIP(req.Context(), &platformv1.AllocateIPRequest{
		PoolId:   body.PoolID,
		DeviceId: body.DeviceID,
		Hostname: body.Hostname,
	})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	r.respWriter.Success201(w, req, allocationProtoToResponse(resp.GetAllocation()))
}

func (r *IPAMRouter) listAllocations(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListAllocations(req.Context(), &platformv1.ListAllocationsRequest{
		PoolId: req.URL.Query().Get("pool_id"),
	})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	allocations := make([]IPAllocationResponse, 0, len(resp.GetAllocations()))
	for _, a := range resp.GetAllocations() {
		allocations = append(allocations, allocationProtoToResponse(a))
	}
	r.respWriter.Success200(w, req, IPAllocationListResponse{
		Allocations: allocations,
		Count:       len(allocations),
		Timestamp:   time.Now().UTC(),
	})
}

func (r *IPAMRouter) release(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	ip := mux.Vars(req)["ip"]
	if _, err := r.server.ReleaseIP(req.Context(), &platformv1.ReleaseIPRequest{
		Ip: ip,
	}); err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	r.respWriter.Success200(w, req, IPAMActionResponse{
		ResourceID:   ip,
		ResourceType: "ip_allocation",
		Action:       "release",
		Success:      true,
		Message:      "IP released successfully",
	})
}

// derefString returns *s, or "" when s is nil.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
