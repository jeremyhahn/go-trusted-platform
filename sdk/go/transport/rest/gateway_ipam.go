// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ipamBasePath is the full gateway IPAM surface
// (pkg/webservice/v1/rest/gateway/ipam.go). Every IPAM verb routes here:
// the reduced /api/v1/gateway/ipam set carries neither pool CRUD nor the
// zone and pool filters.
const ipamBasePath = "/api/v1/sdn/gateway/ipam"

// keepDuration is the UpdateIPAMPoolRequest duration sentinel that keeps
// the pool's current value.
const keepDuration int64 = -1

// ipamJSON decodes the snake_case pool and allocation objects. Their field
// names are the proto names, so protojson maps them straight onto the pb
// messages; the list wrappers' count and timestamp are discarded.
var ipamJSON = protojson.UnmarshalOptions{DiscardUnknown: true}

func init() {
	templatedRouteTable[platformv1.GatewayService_ListIPAMPools_FullMethodName] = templatedRoute{
		path:        ipamBasePath + "/pools",
		method:      http.MethodGet,
		queryParams: []queryParam{{name: "zone", field: "zone"}},
	}
	templatedRouteTable[platformv1.GatewayService_GetIPAMPool_FullMethodName] =
		itemRoute(ipamBasePath+"/pools/{id}", http.MethodGet, "{id}", "id")
	templatedRouteTable[platformv1.GatewayService_UpdateIPAMPool_FullMethodName] =
		itemRoute(ipamBasePath+"/pools/{id}", http.MethodPut, "{id}", "id")
	templatedRouteTable[platformv1.GatewayService_DeleteIPAMPool_FullMethodName] =
		itemRoute(ipamBasePath+"/pools/{id}", http.MethodDelete, "{id}", "id")
	templatedRouteTable[platformv1.GatewayService_ReleaseIP_FullMethodName] =
		itemRoute(ipamBasePath+"/allocations/{ip}", http.MethodDelete, "{ip}", "ip")
	templatedRouteTable[platformv1.GatewayService_ListAllocations_FullMethodName] = templatedRoute{
		path:        ipamBasePath + "/allocations",
		method:      http.MethodGet,
		queryParams: []queryParam{{name: "pool_id", field: "pool_id"}},
	}

	// Create and allocate send the request message as it is: its JSON
	// names are the ones the server's request bodies use.
	grpcMethodToRESTMap[platformv1.GatewayService_CreateIPAMPool_FullMethodName] = struct {
		path   string
		method string
	}{ipamBasePath + "/pools", http.MethodPost}
	grpcMethodToRESTMap[platformv1.GatewayService_AllocateIP_FullMethodName] = struct {
		path   string
		method string
	}{ipamBasePath + "/allocations", http.MethodPost}

	restRequestEncoders[platformv1.GatewayService_UpdateIPAMPool_FullMethodName] = encodeUpdateIPAMPool

	// The two lists decode straight into their replies (see ipamJSON's
	// note); every other reply wraps a bare object or an action result.
	restResponseDecoders[platformv1.GatewayService_GetIPAMPool_FullMethodName] = decodeGetIPAMPool
	restResponseDecoders[platformv1.GatewayService_CreateIPAMPool_FullMethodName] = decodeCreateIPAMPool
	restResponseDecoders[platformv1.GatewayService_UpdateIPAMPool_FullMethodName] = decodeUpdateIPAMPool
	restResponseDecoders[platformv1.GatewayService_DeleteIPAMPool_FullMethodName] = decodeDeleteIPAMPool
	restResponseDecoders[platformv1.GatewayService_AllocateIP_FullMethodName] = decodeAllocateIP
	restResponseDecoders[platformv1.GatewayService_ReleaseIP_FullMethodName] = decodeReleaseIP
}

// ipamPoolUpdateBody is the REST pool update. The server changes only what
// the body names: an omitted field keeps the pool's value, an empty
// reserved list clears it, and an empty range bound clears that bound.
type ipamPoolUpdateBody struct {
	Name                      string    `json:"name,omitempty"`
	Gateway                   string    `json:"gateway,omitempty"`
	Zone                      string    `json:"zone,omitempty"`
	Description               string    `json:"description,omitempty"`
	DefaultLeaseDurationNanos int64     `json:"default_lease_duration_nanos,omitempty"`
	InactivityTimeoutNanos    int64     `json:"inactivity_timeout_nanos,omitempty"`
	Reserved                  *[]string `json:"reserved,omitempty"`
	RangeStart                *string   `json:"range_start,omitempty"`
	RangeEnd                  *string   `json:"range_end,omitempty"`
}

// encodeUpdateIPAMPool maps the gRPC update onto the REST body. A duration
// of keepDuration is omitted, a positive one is sent, and zero is refused
// because REST keeps a duration it is not given. UpdateWindow sends the
// whole window, so an empty bound or reserved list clears it as on gRPC.
func encodeUpdateIPAMPool(body interface{}) (interface{}, error) {
	in, ok := body.(*platformv1.UpdateIPAMPoolRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.GatewayService_UpdateIPAMPool_FullMethodName}
	}
	lease, err := updateDuration("default_lease_duration_nanos", in.GetDefaultLeaseDurationNanos())
	if err != nil {
		return nil, err
	}
	inactivity, err := updateDuration("inactivity_timeout_nanos", in.GetInactivityTimeoutNanos())
	if err != nil {
		return nil, err
	}
	out := ipamPoolUpdateBody{
		Name:                      in.GetName(),
		Gateway:                   in.GetGateway(),
		Zone:                      in.GetZone(),
		Description:               in.GetDescription(),
		DefaultLeaseDurationNanos: lease,
		InactivityTimeoutNanos:    inactivity,
	}
	if in.GetUpdateWindow() {
		reserved := in.GetReserved()
		if reserved == nil {
			reserved = []string{}
		}
		start, end := in.GetRangeStart(), in.GetRangeEnd()
		out.Reserved = &reserved
		out.RangeStart = &start
		out.RangeEnd = &end
	}
	return out, nil
}

// updateDuration returns the REST value for an update duration: zero (so
// omitted) for keepDuration, the value itself when positive.
func updateDuration(field string, nanos int64) (int64, error) {
	if nanos == keepDuration {
		return 0, nil
	}
	if nanos <= 0 {
		return 0, ErrDurationClearNotSupported{Field: field}
	}
	return nanos, nil
}

func unmarshalIPAMPool(raw []byte) (*platformv1.IPAMPool, error) {
	pool := &platformv1.IPAMPool{}
	if err := ipamJSON.Unmarshal(raw, pool); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return pool, nil
}

func unmarshalIPAMStatus(raw []byte) (*platformv1.Status, error) {
	st := &platformv1.Status{}
	if err := ipamJSON.Unmarshal(raw, st); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return st, nil
}

func decodeGetIPAMPool(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetIPAMPoolResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_GetIPAMPool_FullMethodName}
	}
	pool, err := unmarshalIPAMPool(raw)
	if err != nil {
		return err
	}
	out.Pool = pool
	return nil
}

func decodeCreateIPAMPool(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.CreateIPAMPoolResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_CreateIPAMPool_FullMethodName}
	}
	pool, err := unmarshalIPAMPool(raw)
	if err != nil {
		return err
	}
	out.Pool = pool
	out.Status = &platformv1.Status{Success: true}
	return nil
}

func decodeUpdateIPAMPool(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.UpdateIPAMPoolResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_UpdateIPAMPool_FullMethodName}
	}
	pool, err := unmarshalIPAMPool(raw)
	if err != nil {
		return err
	}
	out.Pool = pool
	out.Status = &platformv1.Status{Success: true}
	return nil
}

func decodeDeleteIPAMPool(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.DeleteIPAMPoolResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_DeleteIPAMPool_FullMethodName}
	}
	st, err := unmarshalIPAMStatus(raw)
	if err != nil {
		return err
	}
	out.Status = st
	return nil
}

func decodeAllocateIP(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.AllocateIPResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_AllocateIP_FullMethodName}
	}
	alloc := &platformv1.IPAllocation{}
	if err := ipamJSON.Unmarshal(raw, alloc); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	out.Allocation = alloc
	out.Status = &platformv1.Status{Success: true}
	return nil
}

func decodeReleaseIP(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ReleaseIPResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_ReleaseIP_FullMethodName}
	}
	st, err := unmarshalIPAMStatus(raw)
	if err != nil {
		return err
	}
	out.Status = st
	return nil
}
