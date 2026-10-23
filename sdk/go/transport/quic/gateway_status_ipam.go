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

package quic

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Gateway status, mode set and IPAM ride the gateway category (0x2F). The
// server handler speaks the quicwire shapes in gateway_status.go and
// gateway_ipam.go, so each gRPC request is converted to its wire shape and
// each wire reply back to the gRPC message (#65).

// keepDuration is the gRPC UpdateIPAMPool value that keeps a duration.
const keepDuration int64 = -1

func init() {
	registerCategoryCodecs(gatewayRequestEncoders, gatewayResponseDecoders)
}

var gatewayRequestEncoders = map[string]categoryRequestEncoder{
	platformv1.GatewayService_SetGatewayMode_FullMethodName: requestEncoder(
		platformv1.GatewayService_SetGatewayMode_FullMethodName, encodeGatewaySetModeRequest),
	platformv1.GatewayService_ListIPAMPools_FullMethodName: requestEncoder(
		platformv1.GatewayService_ListIPAMPools_FullMethodName, encodeListIPAMPoolsRequest),
	platformv1.GatewayService_GetIPAMPool_FullMethodName: requestEncoder(
		platformv1.GatewayService_GetIPAMPool_FullMethodName, encodeGetIPAMPoolRequest),
	platformv1.GatewayService_CreateIPAMPool_FullMethodName: requestEncoder(
		platformv1.GatewayService_CreateIPAMPool_FullMethodName, encodeCreateIPAMPoolRequest),
	platformv1.GatewayService_UpdateIPAMPool_FullMethodName: requestEncoder(
		platformv1.GatewayService_UpdateIPAMPool_FullMethodName, encodeUpdateIPAMPoolRequest),
	platformv1.GatewayService_DeleteIPAMPool_FullMethodName: requestEncoder(
		platformv1.GatewayService_DeleteIPAMPool_FullMethodName, encodeDeleteIPAMPoolRequest),
	platformv1.GatewayService_AllocateIP_FullMethodName: requestEncoder(
		platformv1.GatewayService_AllocateIP_FullMethodName, encodeAllocateIPRequest),
	platformv1.GatewayService_ReleaseIP_FullMethodName: requestEncoder(
		platformv1.GatewayService_ReleaseIP_FullMethodName, encodeReleaseIPRequest),
	platformv1.GatewayService_ListAllocations_FullMethodName: requestEncoder(
		platformv1.GatewayService_ListAllocations_FullMethodName, encodeListAllocationsRequest),
}

var gatewayResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.GatewayService_GetGatewayStatus_FullMethodName: decodeGatewayStatusReply,
	platformv1.GatewayService_SetGatewayMode_FullMethodName:   decodeGatewaySetModeReply,
	platformv1.GatewayService_ListIPAMPools_FullMethodName:    decodeListIPAMPoolsReply,
	platformv1.GatewayService_GetIPAMPool_FullMethodName:      decodeGetIPAMPoolReply,
	platformv1.GatewayService_CreateIPAMPool_FullMethodName:   decodeCreateIPAMPoolReply,
	platformv1.GatewayService_UpdateIPAMPool_FullMethodName:   decodeUpdateIPAMPoolReply,
	platformv1.GatewayService_DeleteIPAMPool_FullMethodName:   decodeDeleteIPAMPoolReply,
	platformv1.GatewayService_AllocateIP_FullMethodName:       decodeAllocateIPReply,
	platformv1.GatewayService_ReleaseIP_FullMethodName:        decodeReleaseIPReply,
	platformv1.GatewayService_ListAllocations_FullMethodName:  decodeListAllocationsReply,
}

// ---------------------------------------------------------------------------
// Request encoders
// ---------------------------------------------------------------------------

func encodeGatewaySetModeRequest(in *platformv1.SetGatewayModeRequest) (interface{}, error) {
	return &quicwire.GatewaySetModeRequest{Modes: in.GetModes()}, nil
}

func encodeListIPAMPoolsRequest(in *platformv1.ListIPAMPoolsRequest) (interface{}, error) {
	return &quicwire.GatewayListIPAMPoolsRequest{Zone: in.GetZone()}, nil
}

func encodeGetIPAMPoolRequest(in *platformv1.GetIPAMPoolRequest) (interface{}, error) {
	return &quicwire.GatewayGetIPAMPoolRequest{PoolID: in.GetId()}, nil
}

func encodeCreateIPAMPoolRequest(in *platformv1.CreateIPAMPoolRequest) (interface{}, error) {
	return &quicwire.GatewayCreateIPAMPoolRequest{
		ID:                in.GetId(),
		Name:              in.GetName(),
		CIDR:              in.GetCidr(),
		Gateway:           in.GetGateway(),
		Zone:              in.GetZone(),
		Description:       in.GetDescription(),
		LeaseDuration:     in.GetDefaultLeaseDurationNanos(),
		InactivityTimeout: in.GetInactivityTimeoutNanos(),
		Reserved:          in.GetReserved(),
		RangeStart:        in.GetRangeStart(),
		RangeEnd:          in.GetRangeEnd(),
	}, nil
}

// encodeUpdateIPAMPoolRequest converts the gRPC update to the QUIC one. The
// QUIC update is merge-style: an empty string or a zero duration keeps the
// current value. gRPC keeps a duration with -1 and clears it with 0; the
// clear has no QUIC form, so it is refused rather than silently kept.
func encodeUpdateIPAMPoolRequest(in *platformv1.UpdateIPAMPoolRequest) (interface{}, error) {
	lease, err := quicUpdateDuration("default_lease_duration_nanos", in.GetDefaultLeaseDurationNanos())
	if err != nil {
		return nil, err
	}
	inactivity, err := quicUpdateDuration("inactivity_timeout_nanos", in.GetInactivityTimeoutNanos())
	if err != nil {
		return nil, err
	}
	return &quicwire.GatewayUpdateIPAMPoolRequest{
		PoolID:            in.GetId(),
		Name:              in.GetName(),
		Gateway:           in.GetGateway(),
		Zone:              in.GetZone(),
		Description:       in.GetDescription(),
		LeaseDuration:     lease,
		InactivityTimeout: inactivity,
		UpdateWindow:      in.GetUpdateWindow(),
		Reserved:          in.GetReserved(),
		RangeStart:        in.GetRangeStart(),
		RangeEnd:          in.GetRangeEnd(),
	}, nil
}

// quicUpdateDuration maps a gRPC update duration to its QUIC value: -1
// (keep) becomes 0, a positive value passes through, and 0 (clear) or any
// other negative value is refused.
func quicUpdateDuration(field string, nanos int64) (int64, error) {
	switch {
	case nanos == keepDuration:
		return 0, nil
	case nanos > 0:
		return nanos, nil
	default:
		return 0, ErrDurationClearNotSupported{Field: field}
	}
}

func encodeDeleteIPAMPoolRequest(in *platformv1.DeleteIPAMPoolRequest) (interface{}, error) {
	return &quicwire.GatewayDeleteIPAMPoolRequest{PoolID: in.GetId()}, nil
}

func encodeAllocateIPRequest(in *platformv1.AllocateIPRequest) (interface{}, error) {
	// The QUIC wire names the device the allocation's owner.
	return &quicwire.GatewayAllocateIPRequest{
		PoolID:   in.GetPoolId(),
		Owner:    in.GetDeviceId(),
		Hostname: in.GetHostname(),
	}, nil
}

func encodeReleaseIPRequest(in *platformv1.ReleaseIPRequest) (interface{}, error) {
	return &quicwire.GatewayReleaseIPRequest{IPAddress: in.GetIp()}, nil
}

func encodeListAllocationsRequest(in *platformv1.ListAllocationsRequest) (interface{}, error) {
	return &quicwire.GatewayListAllocationsRequest{PoolID: in.GetPoolId()}, nil
}

// ---------------------------------------------------------------------------
// Reply decoders
// ---------------------------------------------------------------------------

func decodeGatewayStatusReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetGatewayStatusResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_GetGatewayStatus_FullMethodName}
	}
	var wire quicwire.GatewayStatusResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Status = gatewayStatusFromWire(wire.Status)
	return nil
}

func decodeGatewaySetModeReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.SetGatewayModeResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_SetGatewayMode_FullMethodName}
	}
	var wire quicwire.GatewaySetModeResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: wire.Success}
	out.GatewayStatus = gatewayStatusFromWire(wire.Status)
	return nil
}

func decodeListIPAMPoolsReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ListIPAMPoolsResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_ListIPAMPools_FullMethodName}
	}
	var wire quicwire.GatewayListIPAMPoolsResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Pools = make([]*platformv1.IPAMPool, 0, len(wire.Pools))
	for _, pool := range wire.Pools {
		out.Pools = append(out.Pools, ipamPoolFromWire(pool))
	}
	return nil
}

func decodeGetIPAMPoolReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetIPAMPoolResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_GetIPAMPool_FullMethodName}
	}
	var wire quicwire.GatewayGetIPAMPoolResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Pool = ipamPoolFromWire(wire.Pool)
	return nil
}

func decodeCreateIPAMPoolReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.CreateIPAMPoolResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_CreateIPAMPool_FullMethodName}
	}
	var wire quicwire.GatewayCreateIPAMPoolResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: true}
	out.Pool = ipamPoolFromWire(wire.Pool)
	return nil
}

func decodeUpdateIPAMPoolReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.UpdateIPAMPoolResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_UpdateIPAMPool_FullMethodName}
	}
	var wire quicwire.GatewayUpdateIPAMPoolResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: true}
	out.Pool = ipamPoolFromWire(wire.Pool)
	return nil
}

func decodeDeleteIPAMPoolReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.DeleteIPAMPoolResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_DeleteIPAMPool_FullMethodName}
	}
	var wire quicwire.GatewayDeleteIPAMPoolResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: wire.Success}
	return nil
}

func decodeAllocateIPReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.AllocateIPResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_AllocateIP_FullMethodName}
	}
	var wire quicwire.GatewayAllocateIPResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: true}
	out.Allocation = ipAllocationFromWire(wire.Allocation)
	return nil
}

func decodeReleaseIPReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ReleaseIPResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_ReleaseIP_FullMethodName}
	}
	var wire quicwire.GatewayReleaseIPResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: wire.Success}
	return nil
}

func decodeListAllocationsReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ListAllocationsResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.GatewayService_ListAllocations_FullMethodName}
	}
	var wire quicwire.GatewayListAllocationsResponse
	if err := decodeReplyPayload(payload, &wire); err != nil {
		return err
	}
	out.Allocations = make([]*platformv1.IPAllocation, 0, len(wire.Allocations))
	for _, alloc := range wire.Allocations {
		out.Allocations = append(out.Allocations, ipAllocationFromWire(alloc))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Wire to gRPC conversions
// ---------------------------------------------------------------------------

func gatewayStatusFromWire(s *quicwire.GatewayStatusInfo) *platformv1.GatewayStatus {
	if s == nil {
		return nil
	}
	return &platformv1.GatewayStatus{
		Id:            s.ID,
		NodeId:        s.NodeID,
		Modes:         s.Modes,
		Tier:          s.Tier,
		Reputation:    s.Reputation,
		UptimeSeconds: s.UptimeSeconds,
		Healthy:       s.Healthy,
		StartedAt:     unixTimestamp(s.StartedAt),
	}
}

func ipamPoolFromWire(p *quicwire.IPAMPoolInfo) *platformv1.IPAMPool {
	if p == nil {
		return nil
	}
	return &platformv1.IPAMPool{
		Id:                        p.ID,
		Name:                      p.Name,
		Cidr:                      p.CIDR,
		Gateway:                   p.Gateway,
		Zone:                      p.Zone,
		Description:               p.Description,
		Total:                     nonNegative(p.TotalIPs),
		Allocated:                 nonNegative(p.AllocatedIPs),
		Available:                 nonNegative(p.AvailableIPs),
		DefaultLeaseDurationNanos: p.LeaseDuration,
		InactivityTimeoutNanos:    p.InactivityTimeout,
		CreatedAt:                 unixTimestamp(p.CreatedAt),
		UpdatedAt:                 unixTimestamp(p.UpdatedAt),
		Reserved:                  p.Reserved,
		RangeStart:                p.RangeStart,
		RangeEnd:                  p.RangeEnd,
	}
}

func ipAllocationFromWire(a *quicwire.IPAllocationInfo) *platformv1.IPAllocation {
	if a == nil {
		return nil
	}
	return &platformv1.IPAllocation{
		Ip:          a.IPAddress,
		PoolId:      a.PoolID,
		DeviceId:    a.Owner,
		Hostname:    a.Hostname,
		AllocatedAt: unixTimestamp(a.CreatedAt),
		ExpiresAt:   unixTimestamp(a.ExpiresAt),
	}
}

// unixTimestamp converts wire Unix seconds; zero means unset.
func unixTimestamp(seconds int64) *timestamppb.Timestamp {
	if seconds == 0 {
		return nil
	}
	return timestamppb.New(time.Unix(seconds, 0))
}

// nonNegative converts a wire count; a negative count is reported as zero.
func nonNegative(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}
