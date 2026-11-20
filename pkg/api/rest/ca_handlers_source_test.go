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
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// swappableCA is a mutex-guarded CA the test swaps under one handler set.
type swappableCA struct {
	mu sync.Mutex
	ca CAServiceInterface
}

func (s *swappableCA) get() CAServiceInterface {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ca
}

func (s *swappableCA) set(ca CAServiceInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ca = ca
}

func serveCA(router *mux.Router, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func caInfoOf(t *testing.T, rr *httptest.ResponseRecorder) CAInfoResponse {
	t.Helper()
	require.Equal(t, http.StatusOK, rr.Code)
	var resp CAInfoResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return resp
}

func TestCAHandlers_WithCASource_FollowsTheSwap(t *testing.T) {
	src := &swappableCA{}
	h := NewCAHandlers(nil, slog.Default(), nil).WithCASource(src.get)
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	t.Run("an empty source answers 503", func(t *testing.T) {
		for _, path := range []string{
			"/api/v1/ca/info",
			"/api/v1/ca/certificates",
			"/api/v1/ca/bundle",
			"/api/v1/ca/crl",
		} {
			assert.Equal(t, http.StatusServiceUnavailable, serveCA(router, path).Code, path)
		}
	})

	t.Run("after the source holds a CA the handlers serve it", func(t *testing.T) {
		src.set(newMockCAService())
		resp := caInfoOf(t, serveCA(router, "/api/v1/ca/info"))
		assert.True(t, resp.IsInitialized)
		assert.Equal(t, "Test CA", resp.CommonName)
	})

	t.Run("a second swap is served without re-registration", func(t *testing.T) {
		second := newMockCAService()
		second.identity = "Second CA"
		src.set(second)
		resp := caInfoOf(t, serveCA(router, "/api/v1/ca/info"))
		assert.Equal(t, "Second CA", resp.CommonName)
	})

	t.Run("a handler built without a source serves its CA", func(t *testing.T) {
		_, plain := setupCAHandlers(newMockCAService())
		resp := caInfoOf(t, serveCA(plain, "/api/v1/ca/info"))
		assert.Equal(t, "Test CA", resp.CommonName)
	})
}
