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

package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHealthHandler(t *testing.T) {
	t.Run("healthy response", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "test", status: StatusHealthy})
		require.NoError(t, err)

		handler := NewHealthHandler(registry)
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

		var response HealthResponse
		err = json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "healthy", response.Status)
		assert.True(t, response.Healthy)
		assert.Equal(t, 1, len(response.Components))
		assert.Equal(t, "test", response.Components[0].Name)
		assert.NotNil(t, response.Counts)
		assert.Equal(t, 1, response.Counts.Total)
		assert.Equal(t, 1, response.Counts.Healthy)
	})

	t.Run("unhealthy response", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "test", status: StatusUnhealthy})
		require.NoError(t, err)

		handler := NewHealthHandler(registry)
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

		var response HealthResponse
		err = json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "unhealthy", response.Status)
		assert.False(t, response.Healthy)
	})

	t.Run("degraded response", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "test", status: StatusDegraded})
		require.NoError(t, err)

		handler := NewHealthHandler(registry)
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		// Degraded still returns 200 as it's serving
		assert.Equal(t, http.StatusOK, rec.Code)

		var response HealthResponse
		err = json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "degraded", response.Status)
	})

	t.Run("without details", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "test", status: StatusHealthy})
		require.NoError(t, err)

		handler := NewHealthHandler(registry, WithIncludeDetails(false))
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		var response HealthResponse
		err = json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Nil(t, response.Components)
		assert.Nil(t, response.Counts)
	})

	t.Run("with custom timeout", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{
			name:   "slow",
			status: StatusHealthy,
			delay:  100 * time.Millisecond,
		})
		require.NoError(t, err)

		handler := NewHealthHandler(registry, WithHandlerTimeout(50*time.Millisecond))
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		var response HealthResponse
		err = json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		// Should show timeout
		assert.Equal(t, 1, len(response.Components))
		assert.Equal(t, "unknown", response.Components[0].Status)
	})
}

func TestNewLivenessHandler(t *testing.T) {
	t.Run("alive response", func(t *testing.T) {
		probe := NewLivenessProbe(func(ctx context.Context) bool {
			return true
		})

		handler := NewLivenessHandler(probe)
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response ProbeResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "ok", response.Status)
		assert.True(t, response.OK)
	})

	t.Run("not alive response", func(t *testing.T) {
		probe := NewLivenessProbe(func(ctx context.Context) bool {
			return false
		})

		handler := NewLivenessHandler(probe)
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

		var response ProbeResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "fail", response.Status)
		assert.False(t, response.OK)
	})
}

func TestNewReadinessHandler(t *testing.T) {
	t.Run("ready response", func(t *testing.T) {
		probe := NewReadinessProbe(func(ctx context.Context) bool {
			return true
		})

		handler := NewReadinessHandler(probe)
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response ProbeResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "ready", response.Status)
		assert.True(t, response.OK)
	})

	t.Run("not ready response", func(t *testing.T) {
		probe := NewReadinessProbe(func(ctx context.Context) bool {
			return false
		})

		handler := NewReadinessHandler(probe)
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

		var response ProbeResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "not_ready", response.Status)
		assert.False(t, response.OK)
	})
}

func TestNewStartupHandler(t *testing.T) {
	t.Run("started response", func(t *testing.T) {
		probe := NewStartupProbe(func(ctx context.Context) bool {
			return true
		})

		handler := NewStartupHandler(probe)
		req := httptest.NewRequest(http.MethodGet, "/startup", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response ProbeResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "started", response.Status)
		assert.True(t, response.OK)
	})

	t.Run("starting response", func(t *testing.T) {
		probe := NewStartupProbe(func(ctx context.Context) bool {
			return false
		})

		handler := NewStartupHandler(probe)
		req := httptest.NewRequest(http.MethodGet, "/startup", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

		var response ProbeResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "starting", response.Status)
		assert.False(t, response.OK)
	})
}

func TestNewComponentHealthHandler(t *testing.T) {
	t.Run("existing component", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "database", status: StatusHealthy})
		require.NoError(t, err)

		handler := NewComponentHealthHandler(registry, "database")
		req := httptest.NewRequest(http.MethodGet, "/health/database", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response ComponentResponse
		err = json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "database", response.Name)
		assert.Equal(t, "healthy", response.Status)
		assert.True(t, response.Healthy)
	})

	t.Run("non-existent component", func(t *testing.T) {
		registry := NewRegistry()

		handler := NewComponentHealthHandler(registry, "missing")
		req := httptest.NewRequest(http.MethodGet, "/health/missing", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("unhealthy component", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "database", status: StatusUnhealthy})
		require.NoError(t, err)

		handler := NewComponentHealthHandler(registry, "database")
		req := httptest.NewRequest(http.MethodGet, "/health/database", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})

	t.Run("without details", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "database", status: StatusHealthy})
		require.NoError(t, err)

		handler := NewComponentHealthHandler(registry, "database", WithIncludeDetails(false))
		req := httptest.NewRequest(http.MethodGet, "/health/database", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		var response ComponentResponse
		err = json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Nil(t, response.Details)
	})
}

func TestHealthMux(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(&mockChecker{name: "test", status: StatusHealthy})
	require.NoError(t, err)

	livenessProbe := NewLivenessProbe(func(ctx context.Context) bool { return true })
	readinessProbe := NewReadinessProbe(func(ctx context.Context) bool { return true })

	mux := HealthMux(registry, livenessProbe, readinessProbe)

	endpoints := []string{"/health", "/healthz", "/livez", "/ready", "/readyz"}
	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, endpoint, nil)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

func TestHealthMuxWithStartup(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register(&mockChecker{name: "test", status: StatusHealthy})
	require.NoError(t, err)

	livenessProbe := NewLivenessProbe(func(ctx context.Context) bool { return true })
	readinessProbe := NewReadinessProbe(func(ctx context.Context) bool { return true })
	startupProbe := NewStartupProbe(func(ctx context.Context) bool { return true })

	mux := HealthMuxWithStartup(registry, livenessProbe, readinessProbe, startupProbe)

	endpoints := []string{"/health", "/healthz", "/livez", "/ready", "/readyz", "/startup"}
	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, endpoint, nil)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

func TestHandlerOptions(t *testing.T) {
	t.Run("WithHandlerTimeout", func(t *testing.T) {
		config := defaultHandlerConfig()
		WithHandlerTimeout(5 * time.Second)(config)
		assert.Equal(t, 5*time.Second, config.timeout)
	})

	t.Run("WithIncludeDetails", func(t *testing.T) {
		config := defaultHandlerConfig()
		assert.True(t, config.includeDetails)
		WithIncludeDetails(false)(config)
		assert.False(t, config.includeDetails)
	})

	t.Run("WithVerbose", func(t *testing.T) {
		config := defaultHandlerConfig()
		assert.False(t, config.verbose)
		WithVerbose(true)(config)
		assert.True(t, config.verbose)
	})
}
