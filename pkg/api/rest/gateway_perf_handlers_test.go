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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

// mockPerfService implements GatewayPerfServiceInterface with
// programmable behavior.
type mockPerfService struct {
	flowsResp     *PerfFlowsResponse
	datapathResp  *PerfDatapathResponse
	conntrackResp *PerfConntrackResponse
	err           error

	lastFlowsReq *PerfFlowsRequest
	lastBridge   string
	lastZone     int
}

func (m *mockPerfService) GetPerfFlows(ctx context.Context, req *PerfFlowsRequest) (*PerfFlowsResponse, error) {
	m.lastFlowsReq = req
	if m.err != nil {
		return nil, m.err
	}
	return m.flowsResp, nil
}

func (m *mockPerfService) GetPerfDatapath(ctx context.Context, bridge string) (*PerfDatapathResponse, error) {
	m.lastBridge = bridge
	if m.err != nil {
		return nil, m.err
	}
	return m.datapathResp, nil
}

func (m *mockPerfService) GetPerfConntrack(ctx context.Context, zone int) (*PerfConntrackResponse, error) {
	m.lastZone = zone
	if m.err != nil {
		return nil, m.err
	}
	return m.conntrackResp, nil
}

// setupPerfTestHandler builds gateway handlers with a mock perf backend.
func setupPerfTestHandler(perfSvc GatewayPerfServiceInterface) *mux.Router {
	handlers := NewGatewayHandlers(newMockGatewayService(), nil)
	handlers.SetPerfService(perfSvc)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return router
}

func TestHandlePerfFlows(t *testing.T) {
	t.Parallel()

	t.Run("measures flows successfully", func(t *testing.T) {
		t.Parallel()
		svc := &mockPerfService{flowsResp: &PerfFlowsResponse{
			Installed:      500,
			DurationNs:     2_000_000,
			FlowsPerSecond: 250000,
			Batched:        true,
			Bridge:         "br-int",
		}}
		router := setupPerfTestHandler(svc)

		body, _ := json.Marshal(PerfFlowsRequest{Count: 500, Batch: true, Bridge: "br-int"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/perf/flows", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result PerfFlowsResponse
		decodeGatewayResponse(t, resp, &result)
		assert.Equal(t, uint32(500), result.Installed)
		assert.True(t, result.Batched)
		assert.Equal(t, "br-int", result.Bridge)
		assert.Equal(t, int64(2_000_000), result.DurationNs)

		if svc.lastFlowsReq == nil || svc.lastFlowsReq.Count != 500 || !svc.lastFlowsReq.Batch {
			t.Errorf("service received %+v", svc.lastFlowsReq)
		}
	})

	t.Run("returns 503 without perf service", func(t *testing.T) {
		t.Parallel()
		router := setupPerfTestHandler(nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/perf/flows", strings.NewReader("{}"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Result().StatusCode)
	})

	t.Run("returns 400 for malformed body", func(t *testing.T) {
		t.Parallel()
		router := setupPerfTestHandler(&mockPerfService{})

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/perf/flows", strings.NewReader("{not json"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})

	t.Run("returns 400 for invalid count", func(t *testing.T) {
		t.Parallel()
		router := setupPerfTestHandler(&mockPerfService{err: ErrPerfInvalidRequest{Reason: "count"}})

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/perf/flows", strings.NewReader(`{"count":1}`))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})

	t.Run("returns 404 for unknown bridge", func(t *testing.T) {
		t.Parallel()
		router := setupPerfTestHandler(&mockPerfService{err: ErrPerfBridgeNotFound{Bridge: "br-x"}})

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/perf/flows", strings.NewReader(`{"count":1}`))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
	})
}

func TestHandlePerfDatapath(t *testing.T) {
	t.Parallel()

	t.Run("reads datapath counters", func(t *testing.T) {
		t.Parallel()
		svc := &mockPerfService{datapathResp: &PerfDatapathResponse{
			Hits:               5000,
			Misses:             20,
			Lost:               1,
			OffloadedFlowCount: 3,
			HWOffloadEnabled:   true,
			DatapathType:       "system",
			Bridge:             "br-int",
		}}
		router := setupPerfTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/perf/datapath?bridge=br-int", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result PerfDatapathResponse
		decodeGatewayResponse(t, resp, &result)
		assert.Equal(t, uint64(5000), result.Hits)
		assert.Equal(t, uint64(3), result.OffloadedFlowCount)
		assert.True(t, result.HWOffloadEnabled)
		assert.Equal(t, "br-int", svc.lastBridge)
	})

	t.Run("returns 503 without perf service", func(t *testing.T) {
		t.Parallel()
		router := setupPerfTestHandler(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/perf/datapath", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Result().StatusCode)
	})

	t.Run("returns 503 when backend reports not configured", func(t *testing.T) {
		t.Parallel()
		router := setupPerfTestHandler(&mockPerfService{err: ErrPerfNotConfigured{}})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/perf/datapath", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Result().StatusCode)
	})
}

func TestHandlePerfConntrack(t *testing.T) {
	t.Parallel()

	t.Run("summarizes all zones", func(t *testing.T) {
		t.Parallel()
		svc := &mockPerfService{conntrackResp: &PerfConntrackResponse{
			TotalEntries: 4,
			PerZone:      map[uint32]uint64{12: 2, 7: 1, 0: 1},
		}}
		router := setupPerfTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/perf/conntrack", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result PerfConntrackResponse
		decodeGatewayResponse(t, resp, &result)
		assert.Equal(t, uint64(4), result.TotalEntries)
		assert.Equal(t, uint64(2), result.PerZone[12])
		assert.Equal(t, -1, svc.lastZone)
	})

	t.Run("passes explicit zone", func(t *testing.T) {
		t.Parallel()
		svc := &mockPerfService{conntrackResp: &PerfConntrackResponse{TotalEntries: 0}}
		router := setupPerfTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/perf/conntrack?zone=12", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Equal(t, 12, svc.lastZone)
	})

	t.Run("returns 400 for invalid zone", func(t *testing.T) {
		t.Parallel()
		router := setupPerfTestHandler(&mockPerfService{})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/perf/conntrack?zone=notanumber", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})

	t.Run("returns 503 without perf service", func(t *testing.T) {
		t.Parallel()
		router := setupPerfTestHandler(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/perf/conntrack", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Result().StatusCode)
	})
}
