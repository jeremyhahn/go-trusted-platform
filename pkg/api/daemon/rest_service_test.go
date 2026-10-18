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

package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRESTServer(t *testing.T) {
	t.Run("creates REST server with valid config", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)
		require.NotNil(t, server)

		assert.NotNil(t, server.router)
		assert.NotNil(t, server.server)
		assert.False(t, server.IsRunning())
	})

	t.Run("creates REST server with nil logger uses default", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, nil)
		require.NoError(t, err)
		require.NotNil(t, server)
	})
}

func TestRESTServerStartStop(t *testing.T) {
	t.Run("start without TLS fails closed", func(t *testing.T) {
		// Fail-closed contract (#32): absent TLS material the server
		// refuses to start with a typed error and binds no listener.
		config := DefaultConfig()
		config.SkipIAMValidation = true // lifecycle test: the REST auth gate (#550) is not under test here
		config.RESTListenAddr = "127.0.0.1:0"
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		err = server.Start()
		require.Error(t, err)
		var startFailed ErrRESTServerStartFailed
		assert.ErrorAs(t, err, &startFailed)
		assert.False(t, server.IsRunning())
	})

	t.Run("start and stop with TLS", func(t *testing.T) {
		config := DefaultConfig()
		config.SkipIAMValidation = true       // lifecycle test: the REST auth gate (#550) is not under test here
		config.RESTListenAddr = "127.0.0.1:0" // Use random port
		cert := sharedTestTLSCertificate()
		config.TLSCertificate = &cert
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		// Start server
		err = server.Start()
		require.NoError(t, err)
		assert.True(t, server.IsRunning())

		// Start binds the listener synchronously, so the server can be
		// stopped as soon as Start returns.
		// Stop server
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = server.Stop(ctx)
		require.NoError(t, err)
		assert.False(t, server.IsRunning())
	})

	t.Run("start returns error when already running", func(t *testing.T) {
		config := DefaultConfig()
		config.SkipIAMValidation = true // lifecycle test: the REST auth gate (#550) is not under test here
		config.RESTListenAddr = "127.0.0.1:0"
		cert := sharedTestTLSCertificate()
		config.TLSCertificate = &cert
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		err = server.Start()
		require.NoError(t, err)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Stop(ctx)
		}()

		// Try to start again
		err = server.Start()
		assert.Error(t, err)
		var alreadyRunning ErrRESTServerAlreadyRunning
		assert.ErrorAs(t, err, &alreadyRunning)
	})

	t.Run("stop returns error when not running", func(t *testing.T) {
		config := DefaultConfig()
		config.SkipIAMValidation = true // lifecycle test: the REST auth gate (#550) is not under test here
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		ctx := context.Background()
		err = server.Stop(ctx)
		assert.Error(t, err)
		var notRunning ErrRESTServerNotRunning
		assert.ErrorAs(t, err, &notRunning)
	})

	t.Run("force stop returns error when not running", func(t *testing.T) {
		config := DefaultConfig()
		config.SkipIAMValidation = true // lifecycle test: the REST auth gate (#550) is not under test here
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		err = server.ForceStop()
		assert.Error(t, err)
		var notRunning ErrRESTServerNotRunning
		assert.ErrorAs(t, err, &notRunning)
	})
}

func TestRESTServerRouter(t *testing.T) {
	t.Run("returns router for external registration", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		router := server.Router()
		require.NotNil(t, router)
		assert.IsType(t, &mux.Router{}, router)
	})
}

func TestRESTHandlerHealth(t *testing.T) {
	t.Run("returns healthy status", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

		var healthResp HealthResponse
		err = json.NewDecoder(resp.Body).Decode(&healthResp)
		require.NoError(t, err)
		assert.Equal(t, "healthy", healthResp.Status)
		assert.False(t, healthResp.Timestamp.IsZero())
	})
}

func TestRESTHandlerStatus(t *testing.T) {
	t.Run("returns daemon status", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var statusResp StatusResponse
		err = json.NewDecoder(resp.Body).Decode(&statusResp)
		require.NoError(t, err)
		assert.Equal(t, "ready", statusResp.Status)
		assert.NotEmpty(t, statusResp.GoVersion)
		assert.NotEmpty(t, statusResp.System.OS)
		assert.NotEmpty(t, statusResp.System.Arch)
		assert.Greater(t, statusResp.System.NumCPUs, 0)
	})
}

func TestRESTHandlerVersion(t *testing.T) {
	t.Run("returns version info", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var versionResp VersionResponse
		err = json.NewDecoder(resp.Body).Decode(&versionResp)
		require.NoError(t, err)
		assert.NotEmpty(t, versionResp.GoVersion)
	})
}

func TestRESTHandlerListServices(t *testing.T) {
	t.Run("returns empty services list", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/services", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var servicesResp ServicesListResponse
		err = json.NewDecoder(resp.Body).Decode(&servicesResp)
		require.NoError(t, err)
		assert.NotNil(t, servicesResp.Services)
		assert.Equal(t, 0, servicesResp.Count)
	})
}

func TestRESTHandlerGetService(t *testing.T) {
	t.Run("returns 404 for non-existent service", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/services/nonexistent", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		var errResp ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Contains(t, errResp.Error, "not found")
	})
}

func TestRESTHandlerProtocols(t *testing.T) {
	t.Run("returns protocol statuses", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/protocols", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var protocolsResp ProtocolsResponse
		err = json.NewDecoder(resp.Body).Decode(&protocolsResp)
		require.NoError(t, err)
		assert.NotEmpty(t, protocolsResp.Protocols)

		// Check that expected protocols are present
		protocolNames := make(map[string]bool)
		for _, p := range protocolsResp.Protocols {
			protocolNames[p.Name] = true
		}
		assert.True(t, protocolNames["REST"])
		assert.True(t, protocolNames["gRPC"])
		assert.True(t, protocolNames["Unix Socket"])
	})
}

func TestRESTCORSMiddleware(t *testing.T) {
	t.Run("adds CORS headers when enabled", func(t *testing.T) {
		config := DefaultConfig()
		config.RESTConfig.EnableCORS = true
		config.RESTConfig.AllowedOrigins = []string{"https://example.com"}

		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()

		// Need to use the handler with middleware applied
		handler := server.applyMiddleware(server.router)
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "https://example.com", resp.Header.Get("Access-Control-Allow-Origin"))
	})

	t.Run("handles OPTIONS preflight request", func(t *testing.T) {
		config := DefaultConfig()
		config.RESTConfig.EnableCORS = true
		config.RESTConfig.AllowedOrigins = []string{"*"}

		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodOptions, "/api/v1/health", nil)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()

		handler := server.applyMiddleware(server.router)
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})
}

func TestRESTCompressionMiddleware(t *testing.T) {
	t.Run("compresses response when Accept-Encoding gzip", func(t *testing.T) {
		config := DefaultConfig()
		config.RESTConfig.EnableCompression = true

		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()

		handler := server.applyMiddleware(server.router)
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	})

	t.Run("does not compress when Accept-Encoding not set", func(t *testing.T) {
		config := DefaultConfig()
		config.RESTConfig.EnableCompression = true

		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		w := httptest.NewRecorder()

		handler := server.applyMiddleware(server.router)
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Empty(t, resp.Header.Get("Content-Encoding"))
	})
}

func TestRESTRequestIDMiddleware(t *testing.T) {
	t.Run("adds request ID to response", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		w := httptest.NewRecorder()

		handler := server.applyMiddleware(server.router)
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		requestID := resp.Header.Get("X-Request-ID")
		assert.NotEmpty(t, requestID)
	})

	t.Run("uses provided request ID", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		req.Header.Set("X-Request-ID", "custom-request-id-123")
		w := httptest.NewRecorder()

		handler := server.applyMiddleware(server.router)
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		requestID := resp.Header.Get("X-Request-ID")
		assert.Equal(t, "custom-request-id-123", requestID)
	})
}

func TestRESTUtilityFunctions(t *testing.T) {
	t.Run("extractPort extracts port from address", func(t *testing.T) {
		assert.Equal(t, 8443, extractPort("0.0.0.0:8443"))
		assert.Equal(t, 9443, extractPort("localhost:9443"))
		assert.Equal(t, 80, extractPort(":80"))
		assert.Equal(t, 0, extractPort("localhost"))
		assert.Equal(t, 0, extractPort(""))
		assert.Equal(t, 0, extractPort("localhost:abc"))
	})

	t.Run("boolToStatus converts bool to status string", func(t *testing.T) {
		assert.Equal(t, "running", boolToStatus(true))
		assert.Equal(t, "stopped", boolToStatus(false))
	})

	t.Run("getMCPAddress returns address or empty", func(t *testing.T) {
		config := DefaultConfig()
		assert.NotEmpty(t, getMCPAddress(config))

		config.MCPConfig = nil
		assert.Empty(t, getMCPAddress(config))
	})

	t.Run("generateRequestID generates unique IDs", func(t *testing.T) {
		id1 := generateRequestID(1)
		id2 := generateRequestID(2)
		assert.NotEqual(t, id1, id2)
		assert.Contains(t, id1, "-1")
		assert.Contains(t, id2, "-2")
	})
}

func TestRESTErrorTypes(t *testing.T) {
	t.Run("ErrRESTServerAlreadyRunning error message", func(t *testing.T) {
		err := ErrRESTServerAlreadyRunning{}
		assert.Equal(t, "REST server is already running", err.Error())
	})

	t.Run("ErrRESTServerNotRunning error message", func(t *testing.T) {
		err := ErrRESTServerNotRunning{}
		assert.Equal(t, "REST server is not running", err.Error())
	})

	t.Run("ErrRESTServerStartFailed error message", func(t *testing.T) {
		err := ErrRESTServerStartFailed{Reason: "port in use"}
		assert.Contains(t, err.Error(), "port in use")
	})

	t.Run("ErrRESTServerStopFailed error message", func(t *testing.T) {
		err := ErrRESTServerStopFailed{Reason: "timeout"}
		assert.Contains(t, err.Error(), "timeout")
	})
}

func TestRESTServerConfigValidation(t *testing.T) {
	t.Run("validates REST config with valid values", func(t *testing.T) {
		config := DefaultRESTServerConfig()
		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("rejects invalid read timeout", func(t *testing.T) {
		config := DefaultRESTServerConfig()
		config.ReadTimeout = 0
		err := config.Validate()
		assert.Error(t, err)
	})

	t.Run("rejects invalid write timeout", func(t *testing.T) {
		config := DefaultRESTServerConfig()
		config.WriteTimeout = 0
		err := config.Validate()
		assert.Error(t, err)
	})

	t.Run("rejects invalid idle timeout", func(t *testing.T) {
		config := DefaultRESTServerConfig()
		config.IdleTimeout = 0
		err := config.Validate()
		assert.Error(t, err)
	})

	t.Run("rejects invalid max header bytes", func(t *testing.T) {
		config := DefaultRESTServerConfig()
		config.MaxHeaderBytes = 0
		err := config.Validate()
		assert.Error(t, err)
	})

	t.Run("rejects negative rate limit", func(t *testing.T) {
		config := DefaultRESTServerConfig()
		config.RateLimitRequests = -1
		err := config.Validate()
		assert.Error(t, err)
	})

	t.Run("rejects negative rate limit burst", func(t *testing.T) {
		config := DefaultRESTServerConfig()
		config.RateLimitBurst = -1
		err := config.Validate()
		assert.Error(t, err)
	})
}

func TestRESTHandlerWriteJSON(t *testing.T) {
	t.Run("writes JSON response correctly", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		// Suppress logger output during test
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		server, err := NewRESTServer(config, service, logger)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		data := map[string]string{"key": "value"}
		server.writeJSON(w, http.StatusOK, data)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

		var result map[string]string
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		assert.Equal(t, "value", result["key"])
	})
}

func TestRESTHandlerWriteError(t *testing.T) {
	t.Run("writes error response correctly", func(t *testing.T) {
		config := DefaultConfig()
		service, err := NewService(config)
		require.NoError(t, err)

		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		server, err := NewRESTServer(config, service, logger)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		testErr := ErrServiceNotFound{ServiceName: "test"}
		server.writeError(w, http.StatusNotFound, testErr)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		var errResp ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Contains(t, errResp.Error, "test")
		assert.Equal(t, http.StatusNotFound, errResp.Code)
	})
}

func TestRESTMiddlewareChain(t *testing.T) {
	t.Run("applies all middleware in correct order", func(t *testing.T) {
		config := DefaultConfig()
		config.RESTConfig.EnableCORS = true
		config.RESTConfig.EnableCompression = false // Disable to simplify test

		service, err := NewService(config)
		require.NoError(t, err)

		server, err := NewRESTServer(config, service, slog.Default())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		req.Header.Set("Origin", "https://test.com")
		w := httptest.NewRecorder()

		handler := server.applyMiddleware(server.router)
		handler.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		// Should have CORS headers (if origin matches)
		// Should have request ID
		assert.NotEmpty(t, resp.Header.Get("X-Request-ID"))
	})
}

// TestMain handles test setup and cleanup for the daemon package.
// It initializes the QUIC codec before any tests run.
func TestMain(m *testing.M) {
	// Initialize the QUIC codec for all tests in this package.
	// Try MsgPack first, fall back to JSON if not available.
	if quicwire.IsCodecSupported(codec.MsgPack) {
		_ = quicwire.SetDefaultCodecType(codec.MsgPack)
	} else {
		_ = quicwire.SetDefaultCodecType(codec.JSON)
	}

	code := m.Run()
	os.Exit(code)
}
