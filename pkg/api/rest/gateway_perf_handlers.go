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

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// =============================================================================
// Gateway Perf Error Types
// =============================================================================

// ErrPerfNotConfigured is returned when perf operations are attempted but
// the daemon has no OVS-backed perf service.
type ErrPerfNotConfigured struct{}

// Error implements the error interface.
func (e ErrPerfNotConfigured) Error() string {
	return "gateway perf service is not configured"
}

// ErrPerfInvalidRequest is returned for invalid perf request parameters.
type ErrPerfInvalidRequest struct{ Reason string }

// Error implements the error interface.
func (e ErrPerfInvalidRequest) Error() string {
	return "invalid perf request: " + e.Reason
}

// ErrPerfBridgeNotFound is returned when the requested measurement bridge
// does not exist.
type ErrPerfBridgeNotFound struct{ Bridge string }

// Error implements the error interface.
func (e ErrPerfBridgeNotFound) Error() string {
	return "perf bridge not found: " + e.Bridge
}

// =============================================================================
// Gateway Perf Request/Response Types
// =============================================================================
//
// The JSON field names match the proto JSON names of the GatewayService
// perf messages so the MCP tools can return these shapes verbatim.

// PerfFlowsRequest configures one measured flow-programming run.
type PerfFlowsRequest struct {
	Count  uint32 `json:"count"`
	Batch  bool   `json:"batch"`
	Bridge string `json:"bridge,omitempty"`
}

// PerfFlowsResponse reports the measured flow-programming results.
type PerfFlowsResponse struct {
	Installed      uint32  `json:"installed"`
	DurationNs     int64   `json:"duration_ns"`
	FlowsPerSecond float64 `json:"flows_per_second"`
	Batched        bool    `json:"batched"`
	Bridge         string  `json:"bridge"`
}

// PerfDatapathResponse reports live datapath counters.
type PerfDatapathResponse struct {
	Hits               uint64 `json:"hits"`
	Misses             uint64 `json:"misses"`
	Lost               uint64 `json:"lost"`
	OffloadedFlowCount uint64 `json:"offloaded_flow_count"`
	HWOffloadEnabled   bool   `json:"hw_offload_enabled"`
	DatapathType       string `json:"datapath_type"`
	Bridge             string `json:"bridge"`
}

// PerfConntrackResponse summarizes the connection tracking table.
type PerfConntrackResponse struct {
	TotalEntries uint64            `json:"total_entries"`
	PerZone      map[uint32]uint64 `json:"per_zone"`
}

// GatewayPerfServiceInterface is the optional perf backend for the
// gateway REST handlers. When unset, the perf routes return 503.
type GatewayPerfServiceInterface interface {
	// GetPerfFlows measures a real flow install/teardown cycle.
	GetPerfFlows(ctx context.Context, req *PerfFlowsRequest) (*PerfFlowsResponse, error)

	// GetPerfDatapath reads live datapath counters. bridge selects the
	// bridge whose datapath_type is reported ("" = daemon default).
	GetPerfDatapath(ctx context.Context, bridge string) (*PerfDatapathResponse, error)

	// GetPerfConntrack summarizes the conntrack table. zone < 0 covers
	// every zone.
	GetPerfConntrack(ctx context.Context, zone int) (*PerfConntrackResponse, error)
}

// SetPerfService wires the optional perf backend into the gateway
// handlers. A nil backend leaves the perf routes returning 503.
func (h *GatewayHandlers) SetPerfService(perfService GatewayPerfServiceInterface) {
	h.perfService = perfService
}

// registerPerfRoutes registers the performance verification routes.
func (h *GatewayHandlers) registerPerfRoutes(router *mux.Router) {
	// POST: the flow measurement mutates bridge flow tables (ephemeral
	// install + cookie-scoped delete).
	router.HandleFunc("/api/v1/sdn/gateway/perf/flows", h.handlePerfFlows).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/gateway/perf/datapath", h.handlePerfDatapath).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/gateway/perf/conntrack", h.handlePerfConntrack).Methods(http.MethodGet)
}

// handlePerfFlows handles POST /api/v1/sdn/gateway/perf/flows
func (h *GatewayHandlers) handlePerfFlows(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.perfService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPerfNotConfigured{})
		return
	}

	var req PerfFlowsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	result, err := h.perfService.GetPerfFlows(ctx, &req)
	if err != nil {
		h.logger.Error("Perf flow measurement failed", "error", err)
		h.writeGatewayError(w, "perf_flows", err)
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// handlePerfDatapath handles GET /api/v1/sdn/gateway/perf/datapath
func (h *GatewayHandlers) handlePerfDatapath(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.perfService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPerfNotConfigured{})
		return
	}

	result, err := h.perfService.GetPerfDatapath(ctx, r.URL.Query().Get("bridge"))
	if err != nil {
		h.logger.Error("Perf datapath query failed", "error", err)
		h.writeGatewayError(w, "perf_datapath", err)
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// handlePerfConntrack handles GET /api/v1/sdn/gateway/perf/conntrack
func (h *GatewayHandlers) handlePerfConntrack(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.perfService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPerfNotConfigured{})
		return
	}

	zone := -1
	if zoneParam := r.URL.Query().Get("zone"); zoneParam != "" {
		parsed, err := strconv.ParseUint(zoneParam, 10, 16)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrPerfInvalidRequest{Reason: "zone must be 0-65535"})
			return
		}
		zone = int(parsed)
	}

	result, err := h.perfService.GetPerfConntrack(ctx, zone)
	if err != nil {
		h.logger.Error("Perf conntrack query failed", "error", err)
		h.writeGatewayError(w, "perf_conntrack", err)
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}
