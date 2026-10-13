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

//go:build codec_msgpack

package quic

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// gatewayCallRecorder invokes method over the QUIC adapter with the server's
// encoded reply and returns the sender, so a test can read what reached the
// wire.
func gatewayCallRecorder(t *testing.T, method string, args, reply interface{}, wireReply interface{}) *recordingSender {
	t.Helper()
	var encoded []byte
	if wireReply != nil {
		var err error
		encoded, err = quicwire.EncodePayload(wireReply)
		if err != nil {
			t.Fatalf("EncodePayload setup failed: %v", err)
		}
	}
	sender := &recordingSender{respPayload: encoded}
	if err := newConnWithSender(t, sender).Invoke(context.Background(), method, args, reply); err != nil {
		t.Fatalf("Invoke(%s) = %v", method, err)
	}
	if sender.rawOpcode != quicwire.OpGatewayCategory {
		t.Fatalf("opcode = 0x%02X, want the gateway category 0x%02X", sender.rawOpcode, quicwire.OpGatewayCategory)
	}
	return sender
}

// decodeSent decodes the request body the adapter put on the wire after the
// sub-opcode byte, asserting the sub-opcode first.
func decodeSent(t *testing.T, sender *recordingSender, subOpcode byte, into interface{}) {
	t.Helper()
	if len(sender.rawPayload) == 0 || sender.rawPayload[0] != subOpcode {
		t.Fatalf("payload = %x, want sub-opcode 0x%02X first", sender.rawPayload, subOpcode)
	}
	if err := quicwire.DecodePayload(sender.rawPayload[1:], into); err != nil {
		t.Fatalf("payload[1:] decode failed: %v", err)
	}
}

// TestInvoke_GatewayStatus_SendsNoBodyAndDecodesTheServedStatus pins the
// contract with pkg/api/quic's status handler: a sub-opcode-only request and
// a GatewayStatusResponse whose started_at is Unix seconds.
func TestInvoke_GatewayStatus_SendsNoBodyAndDecodesTheServedStatus(t *testing.T) {
	started := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	reply := &platformv1.GetGatewayStatusResponse{}
	sender := gatewayCallRecorder(t, platformv1.GatewayService_GetGatewayStatus_FullMethodName,
		&platformv1.GetGatewayStatusRequest{}, reply,
		&quicwire.GatewayStatusResponse{Status: &quicwire.GatewayStatusInfo{
			ID: "gw-1", NodeID: "node-1", Modes: quicwire.GatewayModeEdge, Tier: "edge",
			Reputation: 0.9, UptimeSeconds: 42, Healthy: true, StartedAt: started.Unix(),
		}})

	if len(sender.rawPayload) != 1 || sender.rawPayload[0] != quicwire.OpGatewayStatus {
		t.Fatalf("payload = %x, want only the status sub-opcode", sender.rawPayload)
	}
	s := reply.GetStatus()
	if s.GetId() != "gw-1" || s.GetNodeId() != "node-1" || s.GetModes() != quicwire.GatewayModeEdge ||
		s.GetTier() != "edge" || s.GetReputation() != 0.9 || s.GetUptimeSeconds() != 42 || !s.GetHealthy() {
		t.Fatalf("status = %+v, want the served values", s)
	}
	if !s.GetStartedAt().AsTime().Equal(started) {
		t.Fatalf("started_at = %v, want %v", s.GetStartedAt().AsTime(), started)
	}
}

func TestInvoke_SetGatewayMode_SendsTheBitmaskAndReportsTheResult(t *testing.T) {
	reply := &platformv1.SetGatewayModeResponse{}
	sender := gatewayCallRecorder(t, platformv1.GatewayService_SetGatewayMode_FullMethodName,
		&platformv1.SetGatewayModeRequest{Modes: quicwire.GatewayModesAll}, reply,
		&quicwire.GatewaySetModeResponse{
			Status:  &quicwire.GatewayStatusInfo{ID: "gw-1", Modes: quicwire.GatewayModesAll},
			Success: true,
		})

	var sent quicwire.GatewaySetModeRequest
	decodeSent(t, sender, quicwire.OpGatewaySetMode, &sent)
	if sent.Modes != quicwire.GatewayModesAll {
		t.Fatalf("sent modes = %d, want %d", sent.Modes, quicwire.GatewayModesAll)
	}
	if !reply.GetStatus().GetSuccess() || reply.GetGatewayStatus().GetModes() != quicwire.GatewayModesAll {
		t.Fatalf("reply = %+v, want success and the applied modes", reply)
	}
}

func TestInvoke_IPAMPoolVerbs_ReachTheServerShape(t *testing.T) {
	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	wirePool := &quicwire.IPAMPoolInfo{
		ID: "pool-1", Name: "lan", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "lan",
		Description: "office", TotalIPs: 254, AllocatedIPs: 4, AvailableIPs: 250,
		LeaseDuration: int64(time.Hour), InactivityTimeout: int64(time.Minute),
		CreatedAt: created.Unix(), Reserved: []string{"10.0.0.0/28"},
		RangeStart: "10.0.0.100", RangeEnd: "10.0.0.200",
	}
	assertPool := func(t *testing.T, p *platformv1.IPAMPool) {
		t.Helper()
		if p.GetId() != "pool-1" || p.GetCidr() != "10.0.0.0/24" || p.GetGateway() != "10.0.0.1" ||
			p.GetZone() != "lan" || p.GetDescription() != "office" ||
			p.GetTotal() != 254 || p.GetAllocated() != 4 || p.GetAvailable() != 250 ||
			p.GetDefaultLeaseDurationNanos() != int64(time.Hour) || p.GetInactivityTimeoutNanos() != int64(time.Minute) ||
			p.GetRangeStart() != "10.0.0.100" || p.GetRangeEnd() != "10.0.0.200" || len(p.GetReserved()) != 1 {
			t.Fatalf("pool = %+v, want the served pool", p)
		}
		if !p.GetCreatedAt().AsTime().Equal(created) || p.GetUpdatedAt() != nil {
			t.Fatalf("created_at = %v updated_at = %v, want %v and unset", p.GetCreatedAt(), p.GetUpdatedAt(), created)
		}
	}

	t.Run("List", func(t *testing.T) {
		reply := &platformv1.ListIPAMPoolsResponse{}
		sender := gatewayCallRecorder(t, platformv1.GatewayService_ListIPAMPools_FullMethodName,
			&platformv1.ListIPAMPoolsRequest{Zone: "lan"}, reply,
			&quicwire.GatewayListIPAMPoolsResponse{Pools: []*quicwire.IPAMPoolInfo{wirePool}, Count: 1})
		var sent quicwire.GatewayListIPAMPoolsRequest
		decodeSent(t, sender, quicwire.OpGatewayListIPAMPools, &sent)
		if sent.Zone != "lan" {
			t.Fatalf("sent zone = %q, want lan", sent.Zone)
		}
		if len(reply.GetPools()) != 1 {
			t.Fatalf("pools = %d, want 1", len(reply.GetPools()))
		}
		assertPool(t, reply.GetPools()[0])
	})

	t.Run("Get", func(t *testing.T) {
		reply := &platformv1.GetIPAMPoolResponse{}
		sender := gatewayCallRecorder(t, platformv1.GatewayService_GetIPAMPool_FullMethodName,
			&platformv1.GetIPAMPoolRequest{Id: "pool-1"}, reply,
			&quicwire.GatewayGetIPAMPoolResponse{Pool: wirePool})
		var sent quicwire.GatewayGetIPAMPoolRequest
		decodeSent(t, sender, quicwire.OpGatewayGetIPAMPool, &sent)
		if sent.PoolID != "pool-1" {
			t.Fatalf("sent pool_id = %q, want pool-1", sent.PoolID)
		}
		assertPool(t, reply.GetPool())
	})

	t.Run("Create", func(t *testing.T) {
		reply := &platformv1.CreateIPAMPoolResponse{}
		sender := gatewayCallRecorder(t, platformv1.GatewayService_CreateIPAMPool_FullMethodName,
			&platformv1.CreateIPAMPoolRequest{
				Id: "pool-1", Name: "lan", Cidr: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "lan",
				Description: "office", DefaultLeaseDurationNanos: int64(time.Hour),
				InactivityTimeoutNanos: int64(time.Minute), Reserved: []string{"10.0.0.0/28"},
				RangeStart: "10.0.0.100", RangeEnd: "10.0.0.200",
			}, reply,
			&quicwire.GatewayCreateIPAMPoolResponse{Pool: wirePool})
		var sent quicwire.GatewayCreateIPAMPoolRequest
		decodeSent(t, sender, quicwire.OpGatewayCreateIPAMPool, &sent)
		if sent.ID != "pool-1" || sent.Name != "lan" || sent.CIDR != "10.0.0.0/24" || sent.Gateway != "10.0.0.1" ||
			sent.Zone != "lan" || sent.Description != "office" || sent.LeaseDuration != int64(time.Hour) ||
			sent.InactivityTimeout != int64(time.Minute) || len(sent.Reserved) != 1 ||
			sent.RangeStart != "10.0.0.100" || sent.RangeEnd != "10.0.0.200" {
			t.Fatalf("sent = %+v, want every create field", sent)
		}
		if !reply.GetStatus().GetSuccess() {
			t.Fatal("create reply status is not success")
		}
		assertPool(t, reply.GetPool())
	})

	t.Run("Update", func(t *testing.T) {
		reply := &platformv1.UpdateIPAMPoolResponse{}
		sender := gatewayCallRecorder(t, platformv1.GatewayService_UpdateIPAMPool_FullMethodName,
			&platformv1.UpdateIPAMPoolRequest{
				Id: "pool-1", Zone: "dmz", DefaultLeaseDurationNanos: keepDuration,
				InactivityTimeoutNanos: int64(time.Minute), UpdateWindow: true,
				RangeStart: "10.0.0.50", RangeEnd: "10.0.0.60",
			}, reply,
			&quicwire.GatewayUpdateIPAMPoolResponse{Pool: wirePool})
		var sent quicwire.GatewayUpdateIPAMPoolRequest
		decodeSent(t, sender, quicwire.OpGatewayUpdateIPAMPool, &sent)
		// -1 (keep) becomes the QUIC wire's zero, which the server keeps.
		if sent.PoolID != "pool-1" || sent.Zone != "dmz" || sent.LeaseDuration != 0 ||
			sent.InactivityTimeout != int64(time.Minute) || !sent.UpdateWindow ||
			sent.RangeStart != "10.0.0.50" || sent.RangeEnd != "10.0.0.60" {
			t.Fatalf("sent = %+v, want the update with the lease kept", sent)
		}
		if !reply.GetStatus().GetSuccess() {
			t.Fatal("update reply status is not success")
		}
		assertPool(t, reply.GetPool())
	})

	t.Run("Delete", func(t *testing.T) {
		reply := &platformv1.DeleteIPAMPoolResponse{}
		sender := gatewayCallRecorder(t, platformv1.GatewayService_DeleteIPAMPool_FullMethodName,
			&platformv1.DeleteIPAMPoolRequest{Id: "pool-1"}, reply,
			&quicwire.GatewayDeleteIPAMPoolResponse{PoolID: "pool-1", Success: true})
		var sent quicwire.GatewayDeleteIPAMPoolRequest
		decodeSent(t, sender, quicwire.OpGatewayDeleteIPAMPool, &sent)
		if sent.PoolID != "pool-1" {
			t.Fatalf("sent pool_id = %q, want pool-1", sent.PoolID)
		}
		if !reply.GetStatus().GetSuccess() {
			t.Fatal("delete reply status is not success")
		}
	})
}

func TestInvoke_IPAllocationVerbs_ReachTheServerShape(t *testing.T) {
	allocated := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	wireAlloc := &quicwire.IPAllocationInfo{
		PoolID: "pool-1", IPAddress: "10.0.0.100", Owner: "dev-1", Hostname: "host-1",
		CreatedAt: allocated.Unix(),
	}
	assertAlloc := func(t *testing.T, a *platformv1.IPAllocation) {
		t.Helper()
		if a.GetIp() != "10.0.0.100" || a.GetPoolId() != "pool-1" || a.GetDeviceId() != "dev-1" || a.GetHostname() != "host-1" {
			t.Fatalf("allocation = %+v, want the served allocation", a)
		}
		if !a.GetAllocatedAt().AsTime().Equal(allocated) || a.GetExpiresAt() != nil {
			t.Fatalf("allocated_at = %v expires_at = %v, want %v and unset", a.GetAllocatedAt(), a.GetExpiresAt(), allocated)
		}
	}

	t.Run("Allocate", func(t *testing.T) {
		reply := &platformv1.AllocateIPResponse{}
		sender := gatewayCallRecorder(t, platformv1.GatewayService_AllocateIP_FullMethodName,
			&platformv1.AllocateIPRequest{PoolId: "pool-1", DeviceId: "dev-1", Hostname: "host-1"}, reply,
			&quicwire.GatewayAllocateIPResponse{Allocation: wireAlloc})
		var sent quicwire.GatewayAllocateIPRequest
		decodeSent(t, sender, quicwire.OpGatewayAllocateIP, &sent)
		if sent.PoolID != "pool-1" || sent.Owner != "dev-1" || sent.Hostname != "host-1" {
			t.Fatalf("sent = %+v, want the device as the owner", sent)
		}
		if !reply.GetStatus().GetSuccess() {
			t.Fatal("allocate reply status is not success")
		}
		assertAlloc(t, reply.GetAllocation())
	})

	t.Run("Release", func(t *testing.T) {
		reply := &platformv1.ReleaseIPResponse{}
		sender := gatewayCallRecorder(t, platformv1.GatewayService_ReleaseIP_FullMethodName,
			&platformv1.ReleaseIPRequest{Ip: "10.0.0.100"}, reply,
			&quicwire.GatewayReleaseIPResponse{IPAddress: "10.0.0.100", Success: true})
		var sent quicwire.GatewayReleaseIPRequest
		decodeSent(t, sender, quicwire.OpGatewayReleaseIP, &sent)
		if sent.IPAddress != "10.0.0.100" {
			t.Fatalf("sent ip_address = %q, want 10.0.0.100", sent.IPAddress)
		}
		if !reply.GetStatus().GetSuccess() {
			t.Fatal("release reply status is not success")
		}
	})

	t.Run("List", func(t *testing.T) {
		reply := &platformv1.ListAllocationsResponse{}
		sender := gatewayCallRecorder(t, platformv1.GatewayService_ListAllocations_FullMethodName,
			&platformv1.ListAllocationsRequest{PoolId: "pool-1"}, reply,
			&quicwire.GatewayListAllocationsResponse{Allocations: []*quicwire.IPAllocationInfo{wireAlloc}, Count: 1})
		var sent quicwire.GatewayListAllocationsRequest
		decodeSent(t, sender, quicwire.OpGatewayListAllocations, &sent)
		if sent.PoolID != "pool-1" {
			t.Fatalf("sent pool_id = %q, want pool-1", sent.PoolID)
		}
		if len(reply.GetAllocations()) != 1 {
			t.Fatalf("allocations = %d, want 1", len(reply.GetAllocations()))
		}
		assertAlloc(t, reply.GetAllocations()[0])
	})
}

// TestInvoke_UpdateIPAMPool_RefusesAZeroDuration: gRPC clears a duration
// with 0, but the QUIC update keeps a zero, so the adapter refuses rather
// than silently keeping the value the caller asked to clear.
func TestInvoke_UpdateIPAMPool_RefusesAZeroDuration(t *testing.T) {
	for _, req := range []*platformv1.UpdateIPAMPoolRequest{
		{Id: "pool-1", DefaultLeaseDurationNanos: 0, InactivityTimeoutNanos: keepDuration},
		{Id: "pool-1", DefaultLeaseDurationNanos: keepDuration, InactivityTimeoutNanos: 0},
	} {
		sender := &recordingSender{}
		err := newConnWithSender(t, sender).Invoke(context.Background(),
			platformv1.GatewayService_UpdateIPAMPool_FullMethodName, req, &platformv1.UpdateIPAMPoolResponse{})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("Invoke(%+v) = %v, want InvalidArgument", req, err)
		}
		if sender.rawCalls != 0 {
			t.Fatalf("a refused update reached the wire (%d calls)", sender.rawCalls)
		}
	}
}

func TestInvoke_GatewayVerb_RefusesTheWrongRequestType(t *testing.T) {
	sender := &recordingSender{}
	err := newConnWithSender(t, sender).Invoke(context.Background(),
		platformv1.GatewayService_AllocateIP_FullMethodName, &platformv1.ReleaseIPRequest{}, &platformv1.AllocateIPResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Invoke() = %v, want InvalidArgument", err)
	}
	if sender.rawCalls != 0 {
		t.Fatalf("a refused request reached the wire (%d calls)", sender.rawCalls)
	}
}

func TestQuicUpdateDuration(t *testing.T) {
	tests := []struct {
		nanos   int64
		want    int64
		refused bool
	}{
		{nanos: keepDuration, want: 0},
		{nanos: int64(time.Hour), want: int64(time.Hour)},
		{nanos: 0, refused: true},
		{nanos: -2, refused: true},
	}
	for _, tt := range tests {
		got, err := quicUpdateDuration("default_lease_duration_nanos", tt.nanos)
		var clearErr ErrDurationClearNotSupported
		if tt.refused {
			if !errors.As(err, &clearErr) || clearErr.Field != "default_lease_duration_nanos" {
				t.Fatalf("quicUpdateDuration(%d) = %v, want ErrDurationClearNotSupported naming the field", tt.nanos, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Fatalf("quicUpdateDuration(%d) = %d, %v; want %d", tt.nanos, got, err, tt.want)
		}
	}
}

func TestErrDurationClearNotSupported_Error(t *testing.T) {
	got := ErrDurationClearNotSupported{Field: "inactivity_timeout_nanos"}.Error()
	want := "QUIC cannot set inactivity_timeout_nanos to zero: the QUIC pool update keeps a zero duration (send -1 to keep it)"
	if got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

// gatewayConvertedMethods is every gateway method this file converts, with a
// value of its request type.
var gatewayConvertedMethods = map[string]proto.Message{
	platformv1.GatewayService_SetGatewayMode_FullMethodName:  &platformv1.SetGatewayModeRequest{},
	platformv1.GatewayService_ListIPAMPools_FullMethodName:   &platformv1.ListIPAMPoolsRequest{},
	platformv1.GatewayService_GetIPAMPool_FullMethodName:     &platformv1.GetIPAMPoolRequest{},
	platformv1.GatewayService_CreateIPAMPool_FullMethodName:  &platformv1.CreateIPAMPoolRequest{},
	platformv1.GatewayService_UpdateIPAMPool_FullMethodName:  &platformv1.UpdateIPAMPoolRequest{DefaultLeaseDurationNanos: keepDuration, InactivityTimeoutNanos: keepDuration},
	platformv1.GatewayService_DeleteIPAMPool_FullMethodName:  &platformv1.DeleteIPAMPoolRequest{},
	platformv1.GatewayService_AllocateIP_FullMethodName:      &platformv1.AllocateIPRequest{},
	platformv1.GatewayService_ReleaseIP_FullMethodName:       &platformv1.ReleaseIPRequest{},
	platformv1.GatewayService_ListAllocations_FullMethodName: &platformv1.ListAllocationsRequest{},
}

func TestGatewayRequestEncoders_AcceptTheirOwnTypeAndRefuseOthers(t *testing.T) {
	for method, req := range gatewayConvertedMethods {
		encode, ok := categoryRequestEncoders[method]
		if !ok {
			t.Fatalf("%s has no request encoder", method)
		}
		if _, err := encode(req); err != nil {
			t.Fatalf("%s encode of its own request = %v", method, err)
		}
		var wrongType ErrInvalidArgsType
		if _, err := encode(&platformv1.GetNAT64StatusRequest{}); !errors.As(err, &wrongType) || wrongType.Method != method {
			t.Fatalf("%s encode of the wrong request = %v, want ErrInvalidArgsType naming the method", method, err)
		}
	}
}

func TestGatewayReplyDecoders_Refusals(t *testing.T) {
	replies := map[string]proto.Message{
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
		decode, ok := categoryResponseDecoders[method]
		if !ok {
			t.Fatalf("%s has no reply decoder", method)
		}
		var wrongType ErrInvalidReplyType
		if err := decode(nil, &platformv1.GetNAT64StatusResponse{}); !errors.As(err, &wrongType) || wrongType.Method != method {
			t.Fatalf("%s decode into the wrong reply = %v, want ErrInvalidReplyType naming the method", method, err)
		}
		var undecodable ErrDecodingFailed
		if err := decode([]byte{0xc1}, reply); !errors.As(err, &undecodable) {
			t.Fatalf("%s decode of garbage = %v, want ErrDecodingFailed", method, err)
		}
	}
}

func TestWireConversions_NilAndEdgeValues(t *testing.T) {
	if gatewayStatusFromWire(nil) != nil || ipamPoolFromWire(nil) != nil || ipAllocationFromWire(nil) != nil {
		t.Fatal("a nil wire value must convert to nil")
	}
	if unixTimestamp(0) != nil {
		t.Fatal("unixTimestamp(0) must be unset")
	}
	if got := unixTimestamp(1700000000).AsTime().Unix(); got != 1700000000 {
		t.Fatalf("unixTimestamp round trip = %d, want 1700000000", got)
	}
	if nonNegative(-3) != 0 || nonNegative(7) != 7 {
		t.Fatalf("nonNegative(-3), nonNegative(7) = %d, %d; want 0, 7", nonNegative(-3), nonNegative(7))
	}
}
