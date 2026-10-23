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
	"context"
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Perf sentinel errors.
var (
	// ErrGatewayPerfNotConfigured is returned when perf operations are
	// requested but the daemon has no OVS-backed perf service.
	ErrGatewayPerfNotConfigured = errors.New("gateway perf service not configured")

	// ErrGatewayPerfInvalidRequest is returned for invalid perf request
	// parameters (e.g. an out-of-range flow count).
	ErrGatewayPerfInvalidRequest = errors.New("invalid perf request")

	// ErrGatewayPerfBridgeNotFound is returned when the requested
	// measurement bridge does not exist.
	ErrGatewayPerfBridgeNotFound = errors.New("perf bridge not found")
)

// The perf wire structs below intentionally carry NO msgpack tags: the
// vmihailenco codec keys maps on Go FIELD NAMES, and these field names
// mirror the generated platformv1 perf messages exactly. That makes the
// QUIC payloads byte-compatible with the SDK transport, which encodes /
// decodes the pb structs directly (pb passthrough).

// GatewayPerfFlowsRequest configures one measured flow-programming run.
type GatewayPerfFlowsRequest struct {
	Count  uint32
	Batch  bool
	Bridge string
}

// PerfFlowsInfo reports the measured flow-programming results.
type PerfFlowsInfo struct {
	Installed      uint32
	DurationNs     int64
	FlowsPerSecond float64
	Batched        bool
	Bridge         string
}

// GatewayPerfDatapathRequest selects the bridge whose datapath type is
// inspected.
type GatewayPerfDatapathRequest struct {
	Bridge string
}

// PerfDatapathInfo reports live datapath counters.
type PerfDatapathInfo struct {
	Hits               uint64
	Misses             uint64
	Lost               uint64
	OffloadedFlowCount uint64
	HwOffloadEnabled   bool
	DatapathType       string
	Bridge             string
}

// GatewayPerfConntrackRequest optionally restricts the summary to one
// conntrack zone (nil = every zone).
type GatewayPerfConntrackRequest struct {
	Zone *uint32
}

// PerfConntrackInfo summarizes the connection tracking table.
type PerfConntrackInfo struct {
	TotalEntries uint64
	PerZone      map[uint32]uint64
}

// GatewayPerfServiceInterface is the optional perf backend of the QUIC
// gateway handler. When unset, the perf sub-opcodes return
// StatusUnavailable.
type GatewayPerfServiceInterface interface {
	// PerfFlows measures a real flow install/teardown cycle.
	PerfFlows(ctx context.Context, bridge string, count uint32, batch bool) (*PerfFlowsInfo, error)

	// PerfDatapath reads live datapath counters.
	PerfDatapath(ctx context.Context, bridge string) (*PerfDatapathInfo, error)

	// PerfConntrack summarizes the conntrack table (nil zone = all).
	PerfConntrack(ctx context.Context, zone *uint32) (*PerfConntrackInfo, error)
}

// SetPerfService wires the optional perf backend into the gateway
// handler.
func (h *GatewayHandler) SetPerfService(perfService GatewayPerfServiceInterface) {
	h.perfService = perfService
}

// gatewayPerfHandlers dispatches perf sub-opcodes (map-based for O(1)
// lookup, matching the load balancer handler convention).
var gatewayPerfHandlers = map[byte]func(*GatewayHandler, context.Context, *quicwire.Request) *quicwire.Response{
	quicwire.OpGatewayPerfFlows:     (*GatewayHandler).handlePerfFlows,
	quicwire.OpGatewayPerfDatapath:  (*GatewayHandler).handlePerfDatapath,
	quicwire.OpGatewayPerfConntrack: (*GatewayHandler).handlePerfConntrack,
}

// perfErrorResponse maps perf sentinel errors to wire statuses.
func (h *GatewayHandler) perfErrorResponse(err error) *quicwire.Response {
	var status byte
	switch {
	case errors.Is(err, ErrGatewayPerfNotConfigured):
		status = quicwire.StatusUnavailable
	case errors.Is(err, ErrGatewayPerfInvalidRequest):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrGatewayPerfBridgeNotFound):
		status = quicwire.StatusNotFound
	default:
		status = quicwire.StatusInternalError
	}
	return h.errorResponse(status, err)
}

// handlePerfFlows measures real flow-programming throughput.
func (h *GatewayHandler) handlePerfFlows(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.perfService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrGatewayPerfNotConfigured)
	}

	var flowsReq GatewayPerfFlowsRequest
	if err := quicwire.DecodePayload(req.Payload, &flowsReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	result, err := h.perfService.PerfFlows(ctx, flowsReq.Bridge, flowsReq.Count, flowsReq.Batch)
	if err != nil {
		h.logger.Error(err, "perf flow measurement failed")
		return h.perfErrorResponse(err)
	}

	payload, err := quicwire.EncodePayload(result)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: payload}
}

// handlePerfDatapath reads live datapath counters.
func (h *GatewayHandler) handlePerfDatapath(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.perfService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrGatewayPerfNotConfigured)
	}

	var dpReq GatewayPerfDatapathRequest
	if err := quicwire.DecodePayload(req.Payload, &dpReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	result, err := h.perfService.PerfDatapath(ctx, dpReq.Bridge)
	if err != nil {
		h.logger.Error(err, "perf datapath query failed")
		return h.perfErrorResponse(err)
	}

	payload, err := quicwire.EncodePayload(result)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: payload}
}

// handlePerfConntrack summarizes the conntrack table.
func (h *GatewayHandler) handlePerfConntrack(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.perfService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrGatewayPerfNotConfigured)
	}

	var ctReq GatewayPerfConntrackRequest
	if err := quicwire.DecodePayload(req.Payload, &ctReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}

	result, err := h.perfService.PerfConntrack(ctx, ctReq.Zone)
	if err != nil {
		h.logger.Error(err, "perf conntrack query failed")
		return h.perfErrorResponse(err)
	}

	payload, err := quicwire.EncodePayload(result)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: payload}
}
