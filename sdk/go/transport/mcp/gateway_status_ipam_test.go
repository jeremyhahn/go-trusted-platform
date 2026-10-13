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

package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// gatewayMethods lists the GatewayService methods this file maps, with the
// tool each one reaches (pkg/api/mcp/gateway_tools.go).
var gatewayMethods = map[string]string{
	platformv1.GatewayService_GetGatewayStatus_FullMethodName: "gateway_status",
	platformv1.GatewayService_SetGatewayMode_FullMethodName:   "gateway_mode_set",
	platformv1.GatewayService_ListIPAMPools_FullMethodName:    "gateway_ipam_pools",
	platformv1.GatewayService_GetIPAMPool_FullMethodName:      "gateway_ipam_pool_get",
	platformv1.GatewayService_CreateIPAMPool_FullMethodName:   "gateway_ipam_pool_create",
	platformv1.GatewayService_UpdateIPAMPool_FullMethodName:   "gateway_ipam_pool_update",
	platformv1.GatewayService_DeleteIPAMPool_FullMethodName:   "gateway_ipam_pool_delete",
	platformv1.GatewayService_AllocateIP_FullMethodName:       "gateway_ipam_allocate",
	platformv1.GatewayService_ReleaseIP_FullMethodName:        "gateway_ipam_release",
	platformv1.GatewayService_ListAllocations_FullMethodName:  "gateway_ipam_allocations",
}

const gatewayTestTime = "2026-10-13T10:00:00Z"

// gatewayStatusResult is the JSON the server's gatewayStatusView encodes to.
func gatewayStatusResult() map[string]interface{} {
	return map[string]interface{}{
		"id":             "gw-1",
		"node_id":        "node-1",
		"modes":          []interface{}{"overlay", "transit"},
		"mode_bitmask":   float64(5),
		"tier":           "datacenter",
		"reputation":     0.75,
		"uptime_seconds": float64(42),
		"healthy":        true,
		"started_at":     gatewayTestTime,
	}
}

// ipamPoolResult is the JSON an ipam.Pool encodes to.
func ipamPoolResult() map[string]interface{} {
	return map[string]interface{}{
		"id":                     "pool-1",
		"name":                   "lab",
		"cidr":                   "10.0.0.0/24",
		"gateway":                "10.0.0.1",
		"zone":                   "control-plane",
		"description":            "lab pool",
		"reserved":               []interface{}{"10.0.0.2/32"},
		"range_start":            "10.0.0.100",
		"range_end":              "10.0.0.200",
		"total_ips":              float64(252),
		"allocated_ips":          float64(2),
		"available_ips":          float64(250),
		"default_lease_duration": float64(3600 * time.Second),
		"inactivity_timeout":     float64(600 * time.Second),
		"created_at":             gatewayTestTime,
		"updated_at":             "0001-01-01T00:00:00Z",
	}
}

// ipAllocationResult is the JSON an ipam.Allocation encodes to.
func ipAllocationResult() map[string]interface{} {
	return map[string]interface{}{
		"id":           "alloc-1",
		"pool_id":      "pool-1",
		"ip":           "10.0.0.100",
		"device_id":    "dev-1",
		"hostname":     "node-a",
		"allocated_at": gatewayTestTime,
		"last_seen":    gatewayTestTime,
		"status":       "active",
	}
}

func assertInvalidArgument(t *testing.T, err error, want string) {
	t.Helper()
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v (err %v), want InvalidArgument", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v, want it to mention %q", err, want)
	}
}

func TestGatewayMCP_EveryMethodHasToolBuilderAndDecoder(t *testing.T) {
	for method, tool := range gatewayMethods {
		if got := grpcMethodToMCPToolMap[method]; got != tool {
			t.Errorf("%s routes to %q, want %q", method, got, tool)
		}
		if _, has := mcpArgBuilders[method]; !has {
			t.Errorf("%s missing argument builder", method)
		}
		if _, has := mcpReplyDecoders[method]; !has {
			t.Errorf("%s missing reply decoder", method)
		}
	}
}

func TestGatewayMCP_StatusAndModeSet(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"gateway_status":   gatewayStatusResult(),
		"gateway_mode_set": gatewayStatusResult(),
	}, &calls)
	conn := a.Connection()

	statusResp := &platformv1.GetGatewayStatusResponse{}
	if err := conn.Invoke(context.Background(), platformv1.GatewayService_GetGatewayStatus_FullMethodName,
		&platformv1.GetGatewayStatusRequest{}, statusResp); err != nil {
		t.Fatalf("GetGatewayStatus: %v", err)
	}
	got := statusResp.GetStatus()
	if got.GetId() != "gw-1" || got.GetNodeId() != "node-1" || got.GetModes() != 5 ||
		got.GetTier() != "datacenter" || got.GetReputation() != 0.75 ||
		got.GetUptimeSeconds() != 42 || !got.GetHealthy() {
		t.Errorf("status = %+v", got)
	}
	if got.GetStartedAt().AsTime().Format(time.RFC3339) != gatewayTestTime {
		t.Errorf("started_at = %v", got.GetStartedAt())
	}

	modeResp := &platformv1.SetGatewayModeResponse{}
	if err := conn.Invoke(context.Background(), platformv1.GatewayService_SetGatewayMode_FullMethodName,
		&platformv1.SetGatewayModeRequest{Modes: 5}, modeResp); err != nil {
		t.Fatalf("SetGatewayMode: %v", err)
	}
	if len(calls) != 2 || calls[0].Name != "gateway_status" || calls[1].Name != "gateway_mode_set" {
		t.Fatalf("calls = %+v", calls)
	}
	if len(calls[0].Arguments) != 0 {
		t.Errorf("status sent arguments %v", calls[0].Arguments)
	}
	modes, _ := calls[1].Arguments["modes"].([]interface{})
	if len(modes) != 2 || modes[0] != "overlay" || modes[1] != "transit" {
		t.Errorf("modes sent = %v, want [overlay transit]", calls[1].Arguments["modes"])
	}
	if !modeResp.GetStatus().GetSuccess() || modeResp.GetGatewayStatus().GetModes() != 5 {
		t.Errorf("mode reply = %+v", modeResp)
	}
}

func TestGatewayMCP_SetMode_RefusesUnknownBits(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{}, &calls)

	err := a.Connection().Invoke(context.Background(), platformv1.GatewayService_SetGatewayMode_FullMethodName,
		&platformv1.SetGatewayModeRequest{Modes: 9}, &platformv1.SetGatewayModeResponse{})

	assertInvalidArgument(t, err, "0x9")
	if len(calls) != 0 {
		t.Errorf("an unknown mode bit reached the server: %+v", calls)
	}
}

func TestGatewayMCP_PoolVerbs(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"gateway_ipam_pools":       map[string]interface{}{"pools": []interface{}{ipamPoolResult()}},
		"gateway_ipam_pool_get":    ipamPoolResult(),
		"gateway_ipam_pool_create": ipamPoolResult(),
		"gateway_ipam_pool_update": ipamPoolResult(),
		"gateway_ipam_pool_delete": map[string]interface{}{"success": true},
	}, &calls)
	conn := a.Connection()
	ctx := context.Background()

	list := &platformv1.ListIPAMPoolsResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_ListIPAMPools_FullMethodName,
		&platformv1.ListIPAMPoolsRequest{Zone: "control-plane"}, list); err != nil {
		t.Fatalf("ListIPAMPools: %v", err)
	}
	if len(list.GetPools()) != 1 {
		t.Fatalf("pools = %+v", list.GetPools())
	}
	pool := list.GetPools()[0]
	if pool.GetId() != "pool-1" || pool.GetCidr() != "10.0.0.0/24" || pool.GetGateway() != "10.0.0.1" ||
		pool.GetZone() != "control-plane" || pool.GetTotal() != 252 || pool.GetAllocated() != 2 ||
		pool.GetAvailable() != 250 || pool.GetRangeStart() != "10.0.0.100" || pool.GetRangeEnd() != "10.0.0.200" {
		t.Errorf("pool = %+v", pool)
	}
	if pool.GetDefaultLeaseDurationNanos() != int64(time.Hour) || pool.GetInactivityTimeoutNanos() != int64(10*time.Minute) {
		t.Errorf("durations = %d / %d", pool.GetDefaultLeaseDurationNanos(), pool.GetInactivityTimeoutNanos())
	}
	if len(pool.GetReserved()) != 1 || pool.GetReserved()[0] != "10.0.0.2/32" {
		t.Errorf("reserved = %v", pool.GetReserved())
	}
	if pool.GetCreatedAt() == nil || pool.GetUpdatedAt() != nil {
		t.Errorf("created_at = %v, updated_at = %v (the zero time is unset)", pool.GetCreatedAt(), pool.GetUpdatedAt())
	}

	get := &platformv1.GetIPAMPoolResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_GetIPAMPool_FullMethodName,
		&platformv1.GetIPAMPoolRequest{Id: "pool-1"}, get); err != nil {
		t.Fatalf("GetIPAMPool: %v", err)
	}
	if get.GetPool().GetName() != "lab" {
		t.Errorf("get = %+v", get)
	}

	create := &platformv1.CreateIPAMPoolResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_CreateIPAMPool_FullMethodName,
		&platformv1.CreateIPAMPoolRequest{
			Name: "lab", Cidr: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "control-plane",
			DefaultLeaseDurationNanos: int64(time.Hour), Reserved: []string{"10.0.0.2/32"},
			RangeStart: "10.0.0.100", RangeEnd: "10.0.0.200",
		}, create); err != nil {
		t.Fatalf("CreateIPAMPool: %v", err)
	}
	if !create.GetStatus().GetSuccess() || create.GetPool().GetId() != "pool-1" {
		t.Errorf("create = %+v", create)
	}

	update := &platformv1.UpdateIPAMPoolResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_UpdateIPAMPool_FullMethodName,
		&platformv1.UpdateIPAMPoolRequest{
			Id: "pool-1", Name: "renamed", Zone: "control-plane",
			DefaultLeaseDurationNanos: keepDuration, InactivityTimeoutNanos: keepDuration,
		}, update); err != nil {
		t.Fatalf("UpdateIPAMPool: %v", err)
	}
	if !update.GetStatus().GetSuccess() || update.GetPool().GetId() != "pool-1" {
		t.Errorf("update = %+v", update)
	}

	del := &platformv1.DeleteIPAMPoolResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_DeleteIPAMPool_FullMethodName,
		&platformv1.DeleteIPAMPoolRequest{Id: "pool-1"}, del); err != nil {
		t.Fatalf("DeleteIPAMPool: %v", err)
	}
	if !del.GetStatus().GetSuccess() {
		t.Errorf("delete = %+v", del)
	}

	if len(calls) != 5 {
		t.Fatalf("calls = %+v", calls)
	}
	if calls[0].Arguments["zone"] != "control-plane" || calls[1].Arguments["pool_id"] != "pool-1" {
		t.Errorf("list/get args = %v / %v", calls[0].Arguments, calls[1].Arguments)
	}
	created := calls[2].Arguments
	if created["name"] != "lab" || created["cidr"] != "10.0.0.0/24" ||
		created["lease_duration_seconds"] != float64(3600) || created["range_start"] != "10.0.0.100" {
		t.Errorf("create args = %v", created)
	}
	updated := calls[3].Arguments
	if updated["pool_id"] != "pool-1" || updated["name"] != "renamed" {
		t.Errorf("update args = %v", updated)
	}
	for _, kept := range []string{"lease_duration_seconds", "reserved", "range_start", "range_end"} {
		if _, sent := updated[kept]; sent {
			t.Errorf("update sent %s; a kept value must be absent so the server keeps it", kept)
		}
	}
	if calls[4].Arguments["pool_id"] != "pool-1" {
		t.Errorf("delete args = %v", calls[4].Arguments)
	}
}

func TestGatewayMCP_UpdateWindowAndLeaseReplace(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{"gateway_ipam_pool_update": ipamPoolResult()}, &calls)

	err := a.Connection().Invoke(context.Background(), platformv1.GatewayService_UpdateIPAMPool_FullMethodName,
		&platformv1.UpdateIPAMPoolRequest{
			Id: "pool-1", DefaultLeaseDurationNanos: int64(time.Minute),
			InactivityTimeoutNanos: keepDuration, UpdateWindow: true,
		}, &platformv1.UpdateIPAMPoolResponse{})
	if err != nil {
		t.Fatalf("UpdateIPAMPool: %v", err)
	}

	args := calls[0].Arguments
	if args["lease_duration_seconds"] != float64(60) {
		t.Errorf("lease_duration_seconds = %v, want 60", args["lease_duration_seconds"])
	}
	// A window update with no values clears: the empty list and the empty
	// bounds are sent, not omitted.
	reserved, isList := args["reserved"].([]interface{})
	if !isList || len(reserved) != 0 {
		t.Errorf("reserved = %#v, want an empty list", args["reserved"])
	}
	if args["range_start"] != "" || args["range_end"] != "" {
		t.Errorf("range = %v..%v, want empty bounds sent", args["range_start"], args["range_end"])
	}
}

func TestGatewayMCP_AllocationVerbs(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"gateway_ipam_allocate":    ipAllocationResult(),
		"gateway_ipam_release":     map[string]interface{}{"success": true},
		"gateway_ipam_allocations": map[string]interface{}{"allocations": []interface{}{ipAllocationResult()}},
	}, &calls)
	conn := a.Connection()
	ctx := context.Background()

	alloc := &platformv1.AllocateIPResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_AllocateIP_FullMethodName,
		&platformv1.AllocateIPRequest{PoolId: "pool-1", DeviceId: "dev-1", Hostname: "node-a"}, alloc); err != nil {
		t.Fatalf("AllocateIP: %v", err)
	}
	got := alloc.GetAllocation()
	if !alloc.GetStatus().GetSuccess() || got.GetIp() != "10.0.0.100" || got.GetPoolId() != "pool-1" ||
		got.GetDeviceId() != "dev-1" || got.GetHostname() != "node-a" {
		t.Errorf("allocate = %+v", alloc)
	}
	if got.GetAllocatedAt() == nil || got.GetExpiresAt() != nil {
		t.Errorf("allocated_at = %v, expires_at = %v (absent is unset)", got.GetAllocatedAt(), got.GetExpiresAt())
	}

	release := &platformv1.ReleaseIPResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_ReleaseIP_FullMethodName,
		&platformv1.ReleaseIPRequest{Ip: "10.0.0.100"}, release); err != nil {
		t.Fatalf("ReleaseIP: %v", err)
	}
	if !release.GetStatus().GetSuccess() {
		t.Errorf("release = %+v", release)
	}

	list := &platformv1.ListAllocationsResponse{}
	if err := conn.Invoke(ctx, platformv1.GatewayService_ListAllocations_FullMethodName,
		&platformv1.ListAllocationsRequest{PoolId: "pool-1"}, list); err != nil {
		t.Fatalf("ListAllocations: %v", err)
	}
	if len(list.GetAllocations()) != 1 || list.GetAllocations()[0].GetIp() != "10.0.0.100" {
		t.Errorf("allocations = %+v", list.GetAllocations())
	}

	if len(calls) != 3 {
		t.Fatalf("calls = %+v", calls)
	}
	allocArgs := calls[0].Arguments
	if allocArgs["pool_id"] != "pool-1" || allocArgs["device_id"] != "dev-1" || allocArgs["hostname"] != "node-a" {
		t.Errorf("allocate args = %v", allocArgs)
	}
	if calls[1].Arguments["ip"] != "10.0.0.100" || calls[2].Arguments["pool_id"] != "pool-1" {
		t.Errorf("release/list args = %v / %v", calls[1].Arguments, calls[2].Arguments)
	}
}

// TestGatewayMCP_PoolRequestsRefuseWhatMCPCannotCarry: a field the tools
// have no argument for, or a duration they cannot express, is refused
// before anything reaches the server.
func TestGatewayMCP_PoolRequestsRefuseWhatMCPCannotCarry(t *testing.T) {
	keep := keepDuration
	tests := []struct {
		name   string
		method string
		req    interface{}
		reply  interface{}
		want   string
	}{
		{"create with a pool ID", platformv1.GatewayService_CreateIPAMPool_FullMethodName,
			&platformv1.CreateIPAMPoolRequest{Id: "mine", Name: "lab", Cidr: "10.0.0.0/24"},
			&platformv1.CreateIPAMPoolResponse{}, "MCP cannot carry id"},
		{"create with an inactivity timeout", platformv1.GatewayService_CreateIPAMPool_FullMethodName,
			&platformv1.CreateIPAMPoolRequest{Name: "lab", Cidr: "10.0.0.0/24", InactivityTimeoutNanos: int64(time.Minute)},
			&platformv1.CreateIPAMPoolResponse{}, "inactivity_timeout_nanos"},
		{"create with a fractional lease", platformv1.GatewayService_CreateIPAMPool_FullMethodName,
			&platformv1.CreateIPAMPoolRequest{Name: "lab", Cidr: "10.0.0.0/24", DefaultLeaseDurationNanos: int64(1500 * time.Millisecond)},
			&platformv1.CreateIPAMPoolResponse{}, "whole seconds"},
		{"update setting the inactivity timeout", platformv1.GatewayService_UpdateIPAMPool_FullMethodName,
			&platformv1.UpdateIPAMPoolRequest{Id: "pool-1", DefaultLeaseDurationNanos: keep},
			&platformv1.UpdateIPAMPoolResponse{}, "inactivity_timeout_nanos"},
		{"update clearing the lease", platformv1.GatewayService_UpdateIPAMPool_FullMethodName,
			&platformv1.UpdateIPAMPoolRequest{Id: "pool-1", InactivityTimeoutNanos: keep},
			&platformv1.UpdateIPAMPoolResponse{}, "cannot set default_lease_duration_nanos to zero"},
		{"update with a fractional lease", platformv1.GatewayService_UpdateIPAMPool_FullMethodName,
			&platformv1.UpdateIPAMPoolRequest{Id: "pool-1", InactivityTimeoutNanos: keep, DefaultLeaseDurationNanos: int64(1500 * time.Millisecond)},
			&platformv1.UpdateIPAMPoolResponse{}, "whole seconds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []toolCall
			a := provisioningTestServer(t, map[string]interface{}{}, &calls)

			err := a.Connection().Invoke(context.Background(), tt.method, tt.req, tt.reply)

			assertInvalidArgument(t, err, tt.want)
			if len(calls) != 0 {
				t.Errorf("the refused request reached the server: %+v", calls)
			}
		})
	}
}

func TestGatewayMCP_BuildersRefuseTheWrongRequestType(t *testing.T) {
	for method := range gatewayMethods {
		_, err := mcpArgBuilders[method](&platformv1.Status{})
		var wrong ErrUnexpectedArgsType
		if !errors.As(err, &wrong) || wrong.Method != method {
			t.Errorf("%s: err = %v, want ErrUnexpectedArgsType", method, err)
		}
	}
}

func TestGatewayMCP_DecodersRefuseTheWrongReplyType(t *testing.T) {
	for method := range gatewayMethods {
		err := mcpReplyDecoders[method](map[string]interface{}{}, &platformv1.Status{})
		var wrong ErrUnexpectedReplyType
		if !errors.As(err, &wrong) || wrong.Method != method {
			t.Errorf("%s: err = %v, want ErrUnexpectedReplyType", method, err)
		}
	}
}

// TestGatewayMCP_DecodersRefuseMalformedResults: a result of the wrong
// shape is an unmarshal failure, and a result that cannot be re-encoded is
// a marshal failure — never a silently empty reply.
func TestGatewayMCP_DecodersRefuseMalformedResults(t *testing.T) {
	replies := map[string]interface{}{
		platformv1.GatewayService_GetGatewayStatus_FullMethodName: &platformv1.GetGatewayStatusResponse{},
		platformv1.GatewayService_SetGatewayMode_FullMethodName:   &platformv1.SetGatewayModeResponse{},
		platformv1.GatewayService_ListIPAMPools_FullMethodName:    &platformv1.ListIPAMPoolsResponse{},
		platformv1.GatewayService_GetIPAMPool_FullMethodName:      &platformv1.GetIPAMPoolResponse{},
		platformv1.GatewayService_CreateIPAMPool_FullMethodName:   &platformv1.CreateIPAMPoolResponse{},
		platformv1.GatewayService_UpdateIPAMPool_FullMethodName:   &platformv1.UpdateIPAMPoolResponse{},
		platformv1.GatewayService_DeleteIPAMPool_FullMethodName:   &platformv1.DeleteIPAMPoolResponse{},
		platformv1.GatewayService_AllocateIP_FullMethodName:       &platformv1.AllocateIPResponse{},
		platformv1.GatewayService_ReleaseIP_FullMethodName:        &platformv1.ReleaseIPResponse{},
		platformv1.GatewayService_ListAllocations_FullMethodName:  &platformv1.ListAllocationsResponse{},
	}
	for method, reply := range replies {
		decode := mcpReplyDecoders[method]

		var unmarshal ErrUnmarshalFailed
		if err := decode("not an object", reply); !errors.As(err, &unmarshal) {
			t.Errorf("%s: wrong shape gave %v, want ErrUnmarshalFailed", method, err)
		}
		var marshal ErrMarshalFailed
		if err := decode(make(chan int), reply); !errors.As(err, &marshal) {
			t.Errorf("%s: unencodable result gave %v, want ErrMarshalFailed", method, err)
		}
	}
}

func TestWholeSeconds(t *testing.T) {
	got, err := wholeSeconds("lease", int64(90*time.Second))
	if err != nil || got != 90 {
		t.Errorf("wholeSeconds(90s) = %d, %v", got, err)
	}
	got, err = wholeSeconds("lease", 0)
	if err != nil || got != 0 {
		t.Errorf("wholeSeconds(0) = %d, %v", got, err)
	}

	_, err = wholeSeconds("lease", int64(time.Millisecond))
	var partial ErrDurationNotWholeSeconds
	if !errors.As(err, &partial) || partial.Field != "lease" || partial.Nanos != int64(time.Millisecond) {
		t.Errorf("wholeSeconds(1ms) err = %v, want ErrDurationNotWholeSeconds", err)
	}
}

func TestTimestampOrNil(t *testing.T) {
	if timestampOrNil(time.Time{}) != nil {
		t.Error("the zero time must map to no timestamp")
	}
	when := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	if got := timestampOrNil(when); got == nil || !got.AsTime().Equal(when) {
		t.Errorf("timestampOrNil(%v) = %v", when, got)
	}
}

func TestGatewayMCPErrors_Messages(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{ErrUnknownGatewayModes{Modes: 8}, "0x8 names an unknown mode"},
		{ErrFieldNotSupported{Method: "/m", Field: "id"}, "MCP cannot carry id for gRPC method /m"},
		{ErrDurationNotWholeSeconds{Field: "lease", Nanos: 5}, "lease in whole seconds; 5ns"},
		{ErrDurationClearNotSupported{Field: "lease"}, "cannot set lease to zero"},
	}
	for _, tt := range tests {
		if !strings.Contains(tt.err.Error(), tt.want) {
			t.Errorf("%T: %q does not mention %q", tt.err, tt.err.Error(), tt.want)
		}
	}
}
