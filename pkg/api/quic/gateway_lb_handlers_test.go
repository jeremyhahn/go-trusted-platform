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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// testLBVIPSpec builds a valid VIP spec.
func testLBVIPSpec() *LBVIPSpec {
	return &LBVIPSpec{
		Address:  "10.100.0.10",
		Port:     443,
		Protocol: "tcp",
		Backends: []*LBBackendSpec{
			{Address: "10.0.1.5", Port: 8443, Weight: 2},
			{Address: "10.0.1.6", Port: 8443},
		},
	}
}

// testLBVIPInfo builds the fake service response.
func testLBVIPInfo() *LBVIPInfo {
	return &LBVIPInfo{
		Address:   "10.100.0.10",
		Port:      443,
		Protocol:  "tcp",
		Algorithm: "hash",
		CTZone:    7,
		GroupID:   0x4C420001,
		Backends: []*LBBackendInfo{
			{Backend: &LBBackendSpec{Address: "10.0.1.5", Port: 8443, Weight: 2}, Healthy: true},
		},
	}
}

// lbRequest encodes an LB sub-opcode request.
func lbRequest(t *testing.T, opcode byte, payload interface{}) *quicwire.Request {
	t.Helper()
	data, err := quicwire.EncodePayload(payload)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	return &quicwire.Request{Opcode: opcode, Payload: data}
}

func TestGatewayLBAddVIP(t *testing.T) {
	handler, service := createTestGatewayHandler()
	service.vipResp = testLBVIPInfo()

	resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBAddVIP,
		&GatewayAddVIPRequest{VIP: testLBVIPSpec()}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02x, payload = %s", resp.Status, resp.Payload)
	}

	var decoded GatewayAddVIPResponse
	if err := quicwire.DecodePayload(resp.Payload, &decoded); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if decoded.VIP == nil || decoded.VIP.Address != "10.100.0.10" || decoded.VIP.GroupID != 0x4C420001 {
		t.Errorf("decoded VIP = %+v", decoded.VIP)
	}
	if service.lastVIPSpec == nil || len(service.lastVIPSpec.Backends) != 2 {
		t.Errorf("service did not receive the VIP spec: %+v", service.lastVIPSpec)
	}
}

func TestGatewayLBAddVIPErrors(t *testing.T) {
	t.Run("missing target", func(t *testing.T) {
		handler, _ := createTestGatewayHandler()
		resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBAddVIP,
			&GatewayAddVIPRequest{VIP: &LBVIPSpec{Address: "10.0.0.1"}}))
		if resp.Status != quicwire.StatusInvalidArgument {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})

	t.Run("invalid address", func(t *testing.T) {
		handler, _ := createTestGatewayHandler()
		spec := testLBVIPSpec()
		spec.Address = "not-an-ip"
		resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBAddVIP,
			&GatewayAddVIPRequest{VIP: spec}))
		if resp.Status != quicwire.StatusInvalidArgument {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})

	t.Run("already exists", func(t *testing.T) {
		handler, service := createTestGatewayHandler()
		service.addVIPErr = ErrGatewayVIPAlreadyExists
		resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBAddVIP,
			&GatewayAddVIPRequest{VIP: testLBVIPSpec()}))
		if resp.Status != quicwire.StatusAlreadyExists {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})

	t.Run("nil service", func(t *testing.T) {
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)
		resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBAddVIP,
			&GatewayAddVIPRequest{VIP: testLBVIPSpec()}))
		if resp.Status != quicwire.StatusUnavailable {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})
}

func TestGatewayLBRemoveVIP(t *testing.T) {
	handler, _ := createTestGatewayHandler()
	resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBRemoveVIP,
		&GatewayRemoveVIPRequest{Protocol: "tcp", Address: "10.100.0.10", Port: 443}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02x, payload = %s", resp.Status, resp.Payload)
	}

	var decoded GatewayRemoveVIPResponse
	if err := quicwire.DecodePayload(resp.Payload, &decoded); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if !decoded.Success {
		t.Error("Success = false")
	}
}

func TestGatewayLBRemoveVIPErrors(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		handler, service := createTestGatewayHandler()
		service.removeVIPErr = ErrGatewayVIPNotFound
		resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBRemoveVIP,
			&GatewayRemoveVIPRequest{Protocol: "tcp", Address: "10.100.0.10", Port: 443}))
		if resp.Status != quicwire.StatusNotFound {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})

	t.Run("missing target", func(t *testing.T) {
		handler, _ := createTestGatewayHandler()
		resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBRemoveVIP,
			&GatewayRemoveVIPRequest{Protocol: "tcp"}))
		if resp.Status != quicwire.StatusInvalidArgument {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})
}

func TestGatewayLBGetVIP(t *testing.T) {
	handler, service := createTestGatewayHandler()
	service.vipResp = testLBVIPInfo()

	resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBGetVIP,
		&GatewayGetVIPRequest{Protocol: "tcp", Address: "10.100.0.10", Port: 443}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02x, payload = %s", resp.Status, resp.Payload)
	}

	var decoded GatewayGetVIPResponse
	if err := quicwire.DecodePayload(resp.Payload, &decoded); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if decoded.VIP == nil || decoded.VIP.CTZone != 7 {
		t.Errorf("decoded VIP = %+v", decoded.VIP)
	}
}

func TestGatewayLBGetVIPNotFound(t *testing.T) {
	handler, service := createTestGatewayHandler()
	service.getVIPErr = ErrGatewayVIPNotFound
	resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBGetVIP,
		&GatewayGetVIPRequest{Protocol: "tcp", Address: "10.100.0.10", Port: 443}))
	if resp.Status != quicwire.StatusNotFound {
		t.Fatalf("status = 0x%02x", resp.Status)
	}
}

func TestGatewayLBListVIPs(t *testing.T) {
	handler, service := createTestGatewayHandler()
	service.vipsResp = []*LBVIPInfo{testLBVIPInfo()}

	resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBListVIPs,
		&GatewayListVIPsRequest{}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02x, payload = %s", resp.Status, resp.Payload)
	}

	var decoded GatewayListVIPsResponse
	if err := quicwire.DecodePayload(resp.Payload, &decoded); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if decoded.Count != 1 || len(decoded.VIPs) != 1 {
		t.Errorf("decoded = %+v", decoded)
	}
}

func TestGatewayLBListVIPsError(t *testing.T) {
	handler, service := createTestGatewayHandler()
	service.listVIPsErr = errors.New("datapath down")
	resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBListVIPs,
		&GatewayListVIPsRequest{}))
	if resp.Status != quicwire.StatusInternalError {
		t.Fatalf("status = 0x%02x", resp.Status)
	}
}

func TestGatewayLBSetVIPBackends(t *testing.T) {
	handler, service := createTestGatewayHandler()
	service.vipResp = testLBVIPInfo()

	resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBSetVIPBackends,
		&GatewaySetVIPBackendsRequest{
			Protocol: "tcp",
			Address:  "10.100.0.10",
			Port:     443,
			Backends: []*LBBackendSpec{{Address: "10.0.1.9", Port: 9000}},
		}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02x, payload = %s", resp.Status, resp.Payload)
	}
}

func TestGatewayLBSetVIPBackendsErrors(t *testing.T) {
	t.Run("invalid vip", func(t *testing.T) {
		handler, service := createTestGatewayHandler()
		service.setVIPBackendsErr = ErrGatewayInvalidVIP
		resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBSetVIPBackends,
			&GatewaySetVIPBackendsRequest{Protocol: "tcp", Address: "10.100.0.10", Port: 443}))
		if resp.Status != quicwire.StatusInvalidArgument {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})

	t.Run("missing target", func(t *testing.T) {
		handler, _ := createTestGatewayHandler()
		resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBSetVIPBackends,
			&GatewaySetVIPBackendsRequest{Address: "10.100.0.10"}))
		if resp.Status != quicwire.StatusInvalidArgument {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})
}

func TestGatewayLBStatus(t *testing.T) {
	handler, service := createTestGatewayHandler()
	service.lbStatusResp = &LBStatusInfo{Active: true, VIPCount: 2, HealthyBackends: 3, TotalBackends: 4}

	resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBStatus,
		&GatewayLBStatusRequest{}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02x, payload = %s", resp.Status, resp.Payload)
	}

	var decoded GatewayLBStatusResponse
	if err := quicwire.DecodePayload(resp.Payload, &decoded); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if decoded.Status == nil || !decoded.Status.Active || decoded.Status.VIPCount != 2 {
		t.Errorf("decoded status = %+v", decoded.Status)
	}
}

func TestGatewayLBStatusUnavailable(t *testing.T) {
	handler, service := createTestGatewayHandler()
	service.lbStatusErr = ErrGatewayFeatureNotConfigured
	resp := handler.HandleRequest(context.Background(), lbRequest(t, quicwire.OpGatewayLBStatus,
		&GatewayLBStatusRequest{}))
	if resp.Status != quicwire.StatusUnavailable {
		t.Fatalf("status = 0x%02x", resp.Status)
	}
}

// TestGatewayLBSubOpcodeRange pins the load balancer sub-opcode assignments
// (0x30-0x35 under OpGatewayCategory) so future services pick a free range.
func TestGatewayLBSubOpcodeRange(t *testing.T) {
	opcodes := map[byte]string{
		quicwire.OpGatewayLBAddVIP:         "add",
		quicwire.OpGatewayLBRemoveVIP:      "remove",
		quicwire.OpGatewayLBGetVIP:         "get",
		quicwire.OpGatewayLBListVIPs:       "list",
		quicwire.OpGatewayLBSetVIPBackends: "set-backends",
		quicwire.OpGatewayLBStatus:         "status",
	}
	if len(opcodes) != 6 {
		t.Fatalf("sub-opcodes overlap: %v", opcodes)
	}
	for op := range opcodes {
		if op < 0x30 || op > 0x35 {
			t.Errorf("sub-opcode 0x%02x outside the 0x30-0x35 LB range", op)
		}
	}
}
