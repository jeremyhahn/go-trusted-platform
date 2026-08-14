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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

// testLBVIPResponse builds the fake service response.
func testLBVIPResponse() *LBVIPResponse {
	return &LBVIPResponse{
		Address:   "10.100.0.10",
		Port:      443,
		Protocol:  "tcp",
		Algorithm: "hash",
		CTZone:    7,
		GroupID:   0x4C420001,
		Backends: []LBBackendStatus{
			{Backend: LBBackend{Address: "10.0.1.5", Port: 8443, Weight: 2}, Healthy: true},
		},
	}
}

func TestHandleAddVIP(t *testing.T) {
	t.Parallel()

	t.Run("adds VIP successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.addVIPResp = testLBVIPResponse()
		_, router := setupGatewayTestHandler(svc)

		body, _ := json.Marshal(LBVIPRequest{
			Address:  "10.100.0.10",
			Port:     443,
			Protocol: "tcp",
			Backends: []LBBackend{{Address: "10.0.1.5", Port: 8443}},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/lb/vips", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var vip LBVIPResponse
		decodeGatewayResponse(t, resp, &vip)
		assert.Equal(t, "10.100.0.10", vip.Address)
		assert.Equal(t, uint32(0x4C420001), vip.GroupID)
	})

	t.Run("returns 409 for duplicate VIP", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.addVIPErr = ErrLBVIPAlreadyExists{}
		_, router := setupGatewayTestHandler(svc)

		body, _ := json.Marshal(LBVIPRequest{Address: "10.100.0.10", Port: 443, Protocol: "tcp"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/lb/vips", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Result().StatusCode)
	})

	t.Run("returns 400 for invalid body", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/lb/vips", bytes.NewReader([]byte("{bogus")))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})

	t.Run("returns 503 without service", func(t *testing.T) {
		t.Parallel()
		handlers := NewGatewayHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/gateway/lb/vips", bytes.NewReader([]byte("{}")))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Result().StatusCode)
	})
}

func TestHandleListVIPs(t *testing.T) {
	t.Parallel()

	t.Run("lists VIPs successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.listVIPsResp = []LBVIPResponse{*testLBVIPResponse()}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/lb/vips", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var list LBVIPListResponse
		decodeGatewayResponse(t, resp, &list)
		assert.Equal(t, 1, list.Count)
		assert.Len(t, list.VIPs, 1)
	})

	t.Run("returns 503 when LB not configured", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.listVIPsErr = ErrLBNotConfigured{}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/lb/vips", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Result().StatusCode)
	})
}

func TestHandleGetVIP(t *testing.T) {
	t.Parallel()

	t.Run("gets VIP successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.getVIPResp = testLBVIPResponse()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/lb/vips/tcp/10.100.0.10/443", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var vip LBVIPResponse
		decodeGatewayResponse(t, resp, &vip)
		assert.Equal(t, uint16(7), vip.CTZone)
	})

	t.Run("returns 404 for unknown VIP", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.getVIPErr = ErrLBVIPNotFound{}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/lb/vips/tcp/10.9.9.9/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
	})

	t.Run("returns 400 for invalid port", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/lb/vips/tcp/10.100.0.10/notaport", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})
}

func TestHandleRemoveVIP(t *testing.T) {
	t.Parallel()

	t.Run("removes VIP successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/gateway/lb/vips/tcp/10.100.0.10/443", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var action GatewayActionResponse
		decodeGatewayResponse(t, resp, &action)
		assert.True(t, action.Success)
		assert.Equal(t, "vip", action.ResourceType)
	})

	t.Run("returns 404 for unknown VIP", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.removeVIPErr = ErrLBVIPNotFound{}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/gateway/lb/vips/tcp/10.9.9.9/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
	})
}

func TestHandleSetVIPBackends(t *testing.T) {
	t.Parallel()

	t.Run("replaces backends successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.setVIPBackendsResp = testLBVIPResponse()
		_, router := setupGatewayTestHandler(svc)

		body, _ := json.Marshal(LBSetBackendsRequest{
			Backends: []LBBackend{{Address: "10.0.1.9", Port: 9000}},
		})
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/gateway/lb/vips/tcp/10.100.0.10/443/backends", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns 400 for invalid backends", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.setVIPBackendsErr = ErrLBInvalidVIP{Reason: "invalid backend address"}
		_, router := setupGatewayTestHandler(svc)

		body, _ := json.Marshal(LBSetBackendsRequest{Backends: []LBBackend{{Address: "bogus", Port: 1}}})
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/gateway/lb/vips/tcp/10.100.0.10/443/backends", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})
}

func TestHandleGetLBStatus(t *testing.T) {
	t.Parallel()

	t.Run("returns status successfully", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.lbStatusResp = &LBStatusResponse{Active: true, VIPCount: 2, HealthyBackends: 3, TotalBackends: 4}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/lb/status", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var lbStatus LBStatusResponse
		decodeGatewayResponse(t, resp, &lbStatus)
		assert.True(t, lbStatus.Active)
		assert.Equal(t, 2, lbStatus.VIPCount)
		assert.False(t, lbStatus.Timestamp.IsZero())
	})

	t.Run("returns 503 when LB not configured", func(t *testing.T) {
		t.Parallel()
		svc := newMockGatewayService()
		svc.lbStatusErr = ErrLBNotConfigured{}
		_, router := setupGatewayTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/lb/status", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Result().StatusCode)
	})
}

func TestLBErrorTypes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "load balancer service is not configured", ErrLBNotConfigured{}.Error())
	assert.Equal(t, "VIP not found", ErrLBVIPNotFound{}.Error())
	assert.Equal(t, "VIP already exists", ErrLBVIPAlreadyExists{}.Error())
	assert.Equal(t, "invalid VIP: bad port", ErrLBInvalidVIP{Reason: "bad port"}.Error())
}
