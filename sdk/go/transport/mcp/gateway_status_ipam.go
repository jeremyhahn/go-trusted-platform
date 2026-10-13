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

// Gateway status, mode and IPAM over MCP (#65). The tools are registered
// in pkg/api/mcp/gateway_tools.go; they take mode names, a pool_id, and a
// lease in whole seconds, and the pool update is merge-style (an empty
// value or a zero duration keeps the current one). The builders below
// translate the pb requests onto that shape and refuse what it cannot
// carry rather than dropping it.

import (
	"encoding/json"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	gatewaysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

// keepDuration is the UpdateIPAMPoolRequest duration value that leaves the
// pool's current duration unchanged.
const keepDuration int64 = -1

// knownGatewayModes is every bit the gateway mode bitmask defines.
const knownGatewayModes = uint32(platformv1.GatewayModeEnum_GATEWAY_MODE_OVERLAY |
	platformv1.GatewayModeEnum_GATEWAY_MODE_EDGE |
	platformv1.GatewayModeEnum_GATEWAY_MODE_TRANSIT)

func init() {
	for method, tool := range map[string]string{
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
	} {
		grpcMethodToMCPToolMap[method] = tool
	}

	for method, build := range map[string]mcpArgBuilder{
		platformv1.GatewayService_GetGatewayStatus_FullMethodName: buildGatewayStatusArgs,
		platformv1.GatewayService_SetGatewayMode_FullMethodName:   buildGatewayModeSetArgs,
		platformv1.GatewayService_ListIPAMPools_FullMethodName:    buildListIPAMPoolsArgs,
		platformv1.GatewayService_GetIPAMPool_FullMethodName:      buildGetIPAMPoolArgs,
		platformv1.GatewayService_CreateIPAMPool_FullMethodName:   buildCreateIPAMPoolArgs,
		platformv1.GatewayService_UpdateIPAMPool_FullMethodName:   buildUpdateIPAMPoolArgs,
		platformv1.GatewayService_DeleteIPAMPool_FullMethodName:   buildDeleteIPAMPoolArgs,
		platformv1.GatewayService_AllocateIP_FullMethodName:       buildAllocateIPArgs,
		platformv1.GatewayService_ReleaseIP_FullMethodName:        buildReleaseIPArgs,
		platformv1.GatewayService_ListAllocations_FullMethodName:  buildListAllocationsArgs,
	} {
		mcpArgBuilders[method] = build
	}

	for method, decode := range map[string]mcpReplyDecoder{
		platformv1.GatewayService_GetGatewayStatus_FullMethodName: decodeGatewayStatusResult,
		platformv1.GatewayService_SetGatewayMode_FullMethodName:   decodeGatewayModeSetResult,
		platformv1.GatewayService_ListIPAMPools_FullMethodName:    decodeListIPAMPoolsResult,
		platformv1.GatewayService_GetIPAMPool_FullMethodName:      decodeGetIPAMPoolResult,
		platformv1.GatewayService_CreateIPAMPool_FullMethodName:   decodeCreateIPAMPoolResult,
		platformv1.GatewayService_UpdateIPAMPool_FullMethodName:   decodeUpdateIPAMPoolResult,
		platformv1.GatewayService_DeleteIPAMPool_FullMethodName:   decodeDeleteIPAMPoolResult,
		platformv1.GatewayService_AllocateIP_FullMethodName:       decodeAllocateIPResult,
		platformv1.GatewayService_ReleaseIP_FullMethodName:        decodeReleaseIPResult,
		platformv1.GatewayService_ListAllocations_FullMethodName:  decodeListAllocationsResult,
	} {
		mcpReplyDecoders[method] = decode
	}
}

// --- argument builders ---

func buildGatewayStatusArgs(args interface{}) (map[string]interface{}, error) {
	if _, ok := args.(*platformv1.GetGatewayStatusRequest); !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_GetGatewayStatus_FullMethodName}
	}
	return map[string]interface{}{}, nil
}

// buildGatewayModeSetArgs sends the bitmask as the mode names the tool
// takes. A bit naming no mode is refused: it has no name to send.
func buildGatewayModeSetArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.SetGatewayModeRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_SetGatewayMode_FullMethodName}
	}
	if in.GetModes()&^knownGatewayModes != 0 {
		return nil, ErrUnknownGatewayModes{Modes: in.GetModes()}
	}
	return map[string]interface{}{"modes": gatewaysvc.ModeNames(in.GetModes())}, nil
}

func buildListIPAMPoolsArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.ListIPAMPoolsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_ListIPAMPools_FullMethodName}
	}
	return map[string]interface{}{"zone": in.GetZone()}, nil
}

func buildGetIPAMPoolArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.GetIPAMPoolRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_GetIPAMPool_FullMethodName}
	}
	return map[string]interface{}{"pool_id": in.GetId()}, nil
}

// buildCreateIPAMPoolArgs refuses a caller-chosen pool ID and an
// inactivity timeout: the create tool has no argument for either, and the
// server would otherwise create a different pool than the one asked for.
func buildCreateIPAMPoolArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.GatewayService_CreateIPAMPool_FullMethodName
	in, ok := args.(*platformv1.CreateIPAMPoolRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	if in.GetId() != "" {
		return nil, ErrFieldNotSupported{Method: method, Field: "id"}
	}
	if in.GetInactivityTimeoutNanos() != 0 {
		return nil, ErrFieldNotSupported{Method: method, Field: "inactivity_timeout_nanos"}
	}
	lease, err := wholeSeconds("default_lease_duration_nanos", in.GetDefaultLeaseDurationNanos())
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"name":                   in.GetName(),
		"cidr":                   in.GetCidr(),
		"gateway":                in.GetGateway(),
		"zone":                   in.GetZone(),
		"description":            in.GetDescription(),
		"lease_duration_seconds": lease,
		"reserved":               in.GetReserved(),
		"range_start":            in.GetRangeStart(),
		"range_end":              in.GetRangeEnd(),
	}, nil
}

// buildUpdateIPAMPoolArgs maps the gRPC update (a duration of -1 keeps it)
// onto the merge-style tool, which keeps any argument it does not receive.
// The window arguments are sent only when UpdateWindow is set, and then
// always, so an empty value clears. Durations the tool cannot express (a
// zero lease, any inactivity timeout) are refused.
func buildUpdateIPAMPoolArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.GatewayService_UpdateIPAMPool_FullMethodName
	in, ok := args.(*platformv1.UpdateIPAMPoolRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	if in.GetInactivityTimeoutNanos() != keepDuration {
		return nil, ErrFieldNotSupported{Method: method, Field: "inactivity_timeout_nanos"}
	}
	out := map[string]interface{}{
		"pool_id":     in.GetId(),
		"name":        in.GetName(),
		"gateway":     in.GetGateway(),
		"zone":        in.GetZone(),
		"description": in.GetDescription(),
	}
	if lease := in.GetDefaultLeaseDurationNanos(); lease != keepDuration {
		if lease <= 0 {
			return nil, ErrDurationClearNotSupported{Field: "default_lease_duration_nanos"}
		}
		seconds, err := wholeSeconds("default_lease_duration_nanos", lease)
		if err != nil {
			return nil, err
		}
		out["lease_duration_seconds"] = seconds
	}
	if in.GetUpdateWindow() {
		reserved := in.GetReserved()
		if reserved == nil {
			// The tool keeps the reserved list when the argument is
			// absent or null; an empty list clears it.
			reserved = []string{}
		}
		out["reserved"] = reserved
		out["range_start"] = in.GetRangeStart()
		out["range_end"] = in.GetRangeEnd()
	}
	return out, nil
}

func buildDeleteIPAMPoolArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.DeleteIPAMPoolRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_DeleteIPAMPool_FullMethodName}
	}
	return map[string]interface{}{"pool_id": in.GetId()}, nil
}

func buildAllocateIPArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.AllocateIPRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_AllocateIP_FullMethodName}
	}
	return map[string]interface{}{
		"pool_id":   in.GetPoolId(),
		"device_id": in.GetDeviceId(),
		"hostname":  in.GetHostname(),
	}, nil
}

func buildReleaseIPArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.ReleaseIPRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_ReleaseIP_FullMethodName}
	}
	return map[string]interface{}{"ip": in.GetIp()}, nil
}

func buildListAllocationsArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.ListAllocationsRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.GatewayService_ListAllocations_FullMethodName}
	}
	return map[string]interface{}{"pool_id": in.GetPoolId()}, nil
}

// wholeSeconds converts a nanosecond duration to the whole seconds the
// tools carry, refusing a value it would have to truncate.
func wholeSeconds(field string, nanos int64) (int64, error) {
	if nanos%int64(time.Second) != 0 {
		return 0, ErrDurationNotWholeSeconds{Field: field, Nanos: nanos}
	}
	return nanos / int64(time.Second), nil
}

// --- reply decoders ---

// gatewayStatusWire is the JSON the gateway_status and gateway_mode_set
// tools return (gatewayStatusView in pkg/api/daemon).
type gatewayStatusWire struct {
	ID            string     `json:"id"`
	NodeID        string     `json:"node_id"`
	ModeBitmask   uint32     `json:"mode_bitmask"`
	Tier          string     `json:"tier"`
	Reputation    float64    `json:"reputation"`
	UptimeSeconds uint64     `json:"uptime_seconds"`
	Healthy       bool       `json:"healthy"`
	StartedAt     *time.Time `json:"started_at"`
}

func (w *gatewayStatusWire) toPb() *platformv1.GatewayStatus {
	out := &platformv1.GatewayStatus{
		Id:            w.ID,
		NodeId:        w.NodeID,
		Modes:         w.ModeBitmask,
		Tier:          w.Tier,
		Reputation:    w.Reputation,
		UptimeSeconds: w.UptimeSeconds,
		Healthy:       w.Healthy,
	}
	if w.StartedAt != nil {
		out.StartedAt = timestamppb.New(*w.StartedAt)
	}
	return out
}

// ipamPoolWire is the JSON form of an IPAM pool (ipam.Pool).
type ipamPoolWire struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	CIDR                 string    `json:"cidr"`
	Gateway              string    `json:"gateway"`
	Zone                 string    `json:"zone"`
	Description          string    `json:"description"`
	Reserved             []string  `json:"reserved"`
	RangeStart           string    `json:"range_start"`
	RangeEnd             string    `json:"range_end"`
	TotalIPs             uint64    `json:"total_ips"`
	AllocatedIPs         uint64    `json:"allocated_ips"`
	AvailableIPs         uint64    `json:"available_ips"`
	DefaultLeaseDuration int64     `json:"default_lease_duration"`
	InactivityTimeout    int64     `json:"inactivity_timeout"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

func (w *ipamPoolWire) toPb() *platformv1.IPAMPool {
	return &platformv1.IPAMPool{
		Id:                        w.ID,
		Name:                      w.Name,
		Cidr:                      w.CIDR,
		Gateway:                   w.Gateway,
		Zone:                      w.Zone,
		Description:               w.Description,
		Total:                     w.TotalIPs,
		Allocated:                 w.AllocatedIPs,
		Available:                 w.AvailableIPs,
		DefaultLeaseDurationNanos: w.DefaultLeaseDuration,
		InactivityTimeoutNanos:    w.InactivityTimeout,
		CreatedAt:                 timestampOrNil(w.CreatedAt),
		UpdatedAt:                 timestampOrNil(w.UpdatedAt),
		Reserved:                  w.Reserved,
		RangeStart:                w.RangeStart,
		RangeEnd:                  w.RangeEnd,
	}
}

// ipAllocationWire is the JSON form of an IP allocation (ipam.Allocation).
type ipAllocationWire struct {
	IP          string    `json:"ip"`
	PoolID      string    `json:"pool_id"`
	DeviceID    string    `json:"device_id"`
	Hostname    string    `json:"hostname"`
	AllocatedAt time.Time `json:"allocated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (w *ipAllocationWire) toPb() *platformv1.IPAllocation {
	return &platformv1.IPAllocation{
		Ip:          w.IP,
		PoolId:      w.PoolID,
		DeviceId:    w.DeviceID,
		Hostname:    w.Hostname,
		AllocatedAt: timestampOrNil(w.AllocatedAt),
		ExpiresAt:   timestampOrNil(w.ExpiresAt),
	}
}

// gatewaySuccessWire is the {"success": true} the delete and release
// tools return.
type gatewaySuccessWire struct {
	Success bool `json:"success"`
}

// timestampOrNil maps the zero time (an unset field) to no timestamp.
func timestampOrNil(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// decodeToolResult re-encodes a tool result and decodes it into wire.
func decodeToolResult(result interface{}, wire interface{}) error {
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, wire); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	return nil
}

func decodeGatewayStatusResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetGatewayStatusResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_GetGatewayStatus_FullMethodName}
	}
	var wire gatewayStatusWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = wire.toPb()
	return nil
}

func decodeGatewayModeSetResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.SetGatewayModeResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_SetGatewayMode_FullMethodName}
	}
	var wire gatewayStatusWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: true}
	out.GatewayStatus = wire.toPb()
	return nil
}

func decodeListIPAMPoolsResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListIPAMPoolsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_ListIPAMPools_FullMethodName}
	}
	var wire struct {
		Pools []ipamPoolWire `json:"pools"`
	}
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Pools = make([]*platformv1.IPAMPool, 0, len(wire.Pools))
	for i := range wire.Pools {
		out.Pools = append(out.Pools, wire.Pools[i].toPb())
	}
	return nil
}

func decodeGetIPAMPoolResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetIPAMPoolResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_GetIPAMPool_FullMethodName}
	}
	var wire ipamPoolWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Pool = wire.toPb()
	return nil
}

func decodeCreateIPAMPoolResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.CreateIPAMPoolResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_CreateIPAMPool_FullMethodName}
	}
	var wire ipamPoolWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: true}
	out.Pool = wire.toPb()
	return nil
}

func decodeUpdateIPAMPoolResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.UpdateIPAMPoolResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_UpdateIPAMPool_FullMethodName}
	}
	var wire ipamPoolWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: true}
	out.Pool = wire.toPb()
	return nil
}

func decodeDeleteIPAMPoolResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DeleteIPAMPoolResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_DeleteIPAMPool_FullMethodName}
	}
	var wire gatewaySuccessWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: wire.Success}
	return nil
}

func decodeAllocateIPResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.AllocateIPResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_AllocateIP_FullMethodName}
	}
	var wire ipAllocationWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: true}
	out.Allocation = wire.toPb()
	return nil
}

func decodeReleaseIPResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ReleaseIPResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_ReleaseIP_FullMethodName}
	}
	var wire gatewaySuccessWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: wire.Success}
	return nil
}

func decodeListAllocationsResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListAllocationsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_ListAllocations_FullMethodName}
	}
	var wire struct {
		Allocations []ipAllocationWire `json:"allocations"`
	}
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Allocations = make([]*platformv1.IPAllocation, 0, len(wire.Allocations))
	for i := range wire.Allocations {
		out.Allocations = append(out.Allocations, wire.Allocations[i].toPb())
	}
	return nil
}
