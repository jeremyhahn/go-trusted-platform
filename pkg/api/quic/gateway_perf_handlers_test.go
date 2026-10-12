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

// testPerfService is a fake GatewayPerfServiceInterface with programmable
// behavior.
type testPerfService struct {
	flowsResp     *PerfFlowsInfo
	datapathResp  *PerfDatapathInfo
	conntrackResp *PerfConntrackInfo
	err           error

	lastBridge string
	lastCount  uint32
	lastBatch  bool
	lastZone   *uint32
}

func (s *testPerfService) PerfFlows(ctx context.Context, bridge string, count uint32, batch bool) (*PerfFlowsInfo, error) {
	s.lastBridge = bridge
	s.lastCount = count
	s.lastBatch = batch
	if s.err != nil {
		return nil, s.err
	}
	return s.flowsResp, nil
}

func (s *testPerfService) PerfDatapath(ctx context.Context, bridge string) (*PerfDatapathInfo, error) {
	s.lastBridge = bridge
	if s.err != nil {
		return nil, s.err
	}
	return s.datapathResp, nil
}

func (s *testPerfService) PerfConntrack(ctx context.Context, zone *uint32) (*PerfConntrackInfo, error) {
	s.lastZone = zone
	if s.err != nil {
		return nil, s.err
	}
	return s.conntrackResp, nil
}

// createTestPerfHandler builds a gateway handler with a fake perf backend.
func createTestPerfHandler() (*GatewayHandler, *testPerfService) {
	handler, _ := createTestGatewayHandler()
	perfService := &testPerfService{}
	handler.SetPerfService(perfService)
	return handler, perfService
}

// perfRequest encodes a perf sub-opcode request.
func perfRequest(t *testing.T, opcode byte, payload interface{}) *quicwire.Request {
	t.Helper()
	data, err := quicwire.EncodePayload(payload)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	return &quicwire.Request{Opcode: opcode, Payload: data}
}

func TestGatewayPerfSubOpcodeRange(t *testing.T) {
	// The perf sub-range must stay within 0x36-0x38 under
	// OpGatewayCategory so future services pick a free range.
	for name, op := range map[string]byte{
		"flows":     quicwire.OpGatewayPerfFlows,
		"datapath":  quicwire.OpGatewayPerfDatapath,
		"conntrack": quicwire.OpGatewayPerfConntrack,
	} {
		if op < 0x36 || op > 0x38 {
			t.Errorf("sub-opcode %s = 0x%02x outside the 0x36-0x38 perf range", name, op)
		}
	}
	// The dispatch map must cover exactly the three perf sub-opcodes.
	if len(gatewayPerfHandlers) != 3 {
		t.Errorf("gatewayPerfHandlers has %d entries, want 3", len(gatewayPerfHandlers))
	}
}

func TestGatewayPerfFlows(t *testing.T) {
	handler, service := createTestPerfHandler()
	service.flowsResp = &PerfFlowsInfo{
		Installed:      500,
		DurationNs:     1_000_000,
		FlowsPerSecond: 500000,
		Batched:        true,
		Bridge:         "br-int",
	}

	resp := handler.HandleRequest(context.Background(), perfRequest(t, quicwire.OpGatewayPerfFlows,
		&GatewayPerfFlowsRequest{Count: 500, Batch: true, Bridge: "br-int"}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02x, payload = %s", resp.Status, resp.Payload)
	}

	var decoded PerfFlowsInfo
	if err := quicwire.DecodePayload(resp.Payload, &decoded); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if decoded.Installed != 500 || !decoded.Batched || decoded.Bridge != "br-int" {
		t.Errorf("decoded = %+v", decoded)
	}
	if decoded.DurationNs != 1_000_000 || decoded.FlowsPerSecond != 500000 {
		t.Errorf("decoded measurement = %+v", decoded)
	}
	if service.lastCount != 500 || !service.lastBatch || service.lastBridge != "br-int" {
		t.Errorf("service received count=%d batch=%v bridge=%q",
			service.lastCount, service.lastBatch, service.lastBridge)
	}
}

func TestGatewayPerfFlowsErrors(t *testing.T) {
	t.Run("no perf service", func(t *testing.T) {
		handler, _ := createTestGatewayHandler()
		resp := handler.HandleRequest(context.Background(), perfRequest(t, quicwire.OpGatewayPerfFlows,
			&GatewayPerfFlowsRequest{Count: 10}))
		if resp.Status != quicwire.StatusUnavailable {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})

	t.Run("invalid count", func(t *testing.T) {
		handler, service := createTestPerfHandler()
		service.err = ErrGatewayPerfInvalidRequest
		resp := handler.HandleRequest(context.Background(), perfRequest(t, quicwire.OpGatewayPerfFlows,
			&GatewayPerfFlowsRequest{Count: 10}))
		if resp.Status != quicwire.StatusInvalidArgument {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})

	t.Run("bridge not found", func(t *testing.T) {
		handler, service := createTestPerfHandler()
		service.err = ErrGatewayPerfBridgeNotFound
		resp := handler.HandleRequest(context.Background(), perfRequest(t, quicwire.OpGatewayPerfFlows,
			&GatewayPerfFlowsRequest{Count: 10, Bridge: "br-missing"}))
		if resp.Status != quicwire.StatusNotFound {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})

	t.Run("internal error", func(t *testing.T) {
		handler, service := createTestPerfHandler()
		service.err = errors.New("boom")
		resp := handler.HandleRequest(context.Background(), perfRequest(t, quicwire.OpGatewayPerfFlows,
			&GatewayPerfFlowsRequest{Count: 10}))
		if resp.Status != quicwire.StatusInternalError {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})
}

func TestGatewayPerfDatapath(t *testing.T) {
	handler, service := createTestPerfHandler()
	service.datapathResp = &PerfDatapathInfo{
		Hits:               5000,
		Misses:             20,
		Lost:               1,
		OffloadedFlowCount: 3,
		HwOffloadEnabled:   true,
		DatapathType:       "system",
		Bridge:             "br-int",
	}

	resp := handler.HandleRequest(context.Background(), perfRequest(t, quicwire.OpGatewayPerfDatapath,
		&GatewayPerfDatapathRequest{Bridge: "br-int"}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02x, payload = %s", resp.Status, resp.Payload)
	}

	var decoded PerfDatapathInfo
	if err := quicwire.DecodePayload(resp.Payload, &decoded); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if decoded.Hits != 5000 || decoded.OffloadedFlowCount != 3 || !decoded.HwOffloadEnabled {
		t.Errorf("decoded = %+v", decoded)
	}
	if decoded.DatapathType != "system" {
		t.Errorf("DatapathType = %q", decoded.DatapathType)
	}
}

func TestGatewayPerfDatapathErrors(t *testing.T) {
	t.Run("no perf service", func(t *testing.T) {
		handler, _ := createTestGatewayHandler()
		resp := handler.HandleRequest(context.Background(), perfRequest(t, quicwire.OpGatewayPerfDatapath,
			&GatewayPerfDatapathRequest{}))
		if resp.Status != quicwire.StatusUnavailable {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})

	t.Run("not configured", func(t *testing.T) {
		handler, service := createTestPerfHandler()
		service.err = ErrGatewayPerfNotConfigured
		resp := handler.HandleRequest(context.Background(), perfRequest(t, quicwire.OpGatewayPerfDatapath,
			&GatewayPerfDatapathRequest{}))
		if resp.Status != quicwire.StatusUnavailable {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})
}

func TestGatewayPerfConntrack(t *testing.T) {
	handler, service := createTestPerfHandler()
	service.conntrackResp = &PerfConntrackInfo{
		TotalEntries: 4,
		PerZone:      map[uint32]uint64{12: 2, 7: 1, 0: 1},
	}

	zone := uint32(12)
	resp := handler.HandleRequest(context.Background(), perfRequest(t, quicwire.OpGatewayPerfConntrack,
		&GatewayPerfConntrackRequest{Zone: &zone}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02x, payload = %s", resp.Status, resp.Payload)
	}

	var decoded PerfConntrackInfo
	if err := quicwire.DecodePayload(resp.Payload, &decoded); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if decoded.TotalEntries != 4 || decoded.PerZone[12] != 2 {
		t.Errorf("decoded = %+v", decoded)
	}
	if service.lastZone == nil || *service.lastZone != 12 {
		t.Errorf("service received zone = %v, want 12", service.lastZone)
	}
}

func TestGatewayPerfConntrackAllZones(t *testing.T) {
	handler, service := createTestPerfHandler()
	service.conntrackResp = &PerfConntrackInfo{TotalEntries: 0, PerZone: map[uint32]uint64{}}

	resp := handler.HandleRequest(context.Background(), perfRequest(t, quicwire.OpGatewayPerfConntrack,
		&GatewayPerfConntrackRequest{}))
	if resp.Status != quicwire.StatusOK {
		t.Fatalf("status = 0x%02x", resp.Status)
	}
	if service.lastZone != nil {
		t.Errorf("service received zone = %v, want nil (all zones)", service.lastZone)
	}
}

func TestGatewayPerfConntrackErrors(t *testing.T) {
	t.Run("no perf service", func(t *testing.T) {
		handler, _ := createTestGatewayHandler()
		resp := handler.HandleRequest(context.Background(), perfRequest(t, quicwire.OpGatewayPerfConntrack,
			&GatewayPerfConntrackRequest{}))
		if resp.Status != quicwire.StatusUnavailable {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})

	t.Run("internal error", func(t *testing.T) {
		handler, service := createTestPerfHandler()
		service.err = errors.New("boom")
		resp := handler.HandleRequest(context.Background(), perfRequest(t, quicwire.OpGatewayPerfConntrack,
			&GatewayPerfConntrackRequest{}))
		if resp.Status != quicwire.StatusInternalError {
			t.Fatalf("status = 0x%02x", resp.Status)
		}
	})
}
