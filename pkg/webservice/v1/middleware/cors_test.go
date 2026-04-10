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

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCORSMiddleware(t *testing.T) {
	t.Run("sets CORS headers for allowed origin", func(t *testing.T) {
		options := CORSOptions{
			AllowedOrigins:   []string{"https://example.com"},
			AllowedMethods:   []string{"GET", "POST"},
			AllowedHeaders:   []string{"Content-Type", "Authorization"},
			AllowCredentials: true,
		}

		handler := CORSMiddleware(options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, "https://example.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST", rec.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Content-Type, Authorization", rec.Header().Get("Access-Control-Allow-Headers"))
		assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "OK", rec.Body.String())
	})

	t.Run("does not set CORS headers for disallowed origin", func(t *testing.T) {
		options := CORSOptions{
			AllowedOrigins: []string{"https://example.com"},
			AllowedMethods: []string{"GET", "POST"},
			AllowedHeaders: []string{"Content-Type"},
		}

		handler := CORSMiddleware(options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://malicious.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Methods"))
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Headers"))
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("handles preflight OPTIONS request for allowed origin", func(t *testing.T) {
		options := CORSOptions{
			AllowedOrigins: []string{"https://example.com"},
			AllowedMethods: []string{"GET", "POST", "PUT"},
			AllowedHeaders: []string{"Content-Type", "Authorization"},
		}

		nextHandlerCalled := false
		handler := CORSMiddleware(options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextHandlerCalled = true
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodOptions, "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, "https://example.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST, PUT", rec.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Content-Type, Authorization", rec.Header().Get("Access-Control-Allow-Headers"))
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.False(t, nextHandlerCalled, "next handler should not be called for OPTIONS")
	})

	t.Run("handles wildcard origin", func(t *testing.T) {
		options := CORSOptions{
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET"},
			AllowedHeaders: []string{"Content-Type"},
		}

		handler := CORSMiddleware(options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://any-domain.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, "https://any-domain.com", rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("handles multiple allowed origins", func(t *testing.T) {
		options := CORSOptions{
			AllowedOrigins: []string{
				"https://example.com",
				"https://example.org",
				"http://localhost:3000",
			},
			AllowedMethods: []string{"GET"},
			AllowedHeaders: []string{"Content-Type"},
		}

		handler := CORSMiddleware(options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		testOrigins := []string{
			"https://example.com",
			"https://example.org",
			"http://localhost:3000",
		}

		for _, origin := range testOrigins {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, origin, rec.Header().Get("Access-Control-Allow-Origin"),
				"origin %s should be allowed", origin)
		}
	})

	t.Run("does not set credentials header when disabled", func(t *testing.T) {
		options := CORSOptions{
			AllowedOrigins:   []string{"https://example.com"},
			AllowedMethods:   []string{"GET"},
			AllowedHeaders:   []string{"Content-Type"},
			AllowCredentials: false,
		}

		handler := CORSMiddleware(options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
	})

	t.Run("handles empty allowed origins list", func(t *testing.T) {
		options := CORSOptions{
			AllowedOrigins: []string{},
			AllowedMethods: []string{"GET"},
			AllowedHeaders: []string{"Content-Type"},
		}

		handler := CORSMiddleware(options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("handles request without origin header", func(t *testing.T) {
		options := CORSOptions{
			AllowedOrigins: []string{"https://example.com"},
			AllowedMethods: []string{"GET"},
			AllowedHeaders: []string{"Content-Type"},
		}

		handler := CORSMiddleware(options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "OK", rec.Body.String())
	})

	t.Run("handles empty methods list", func(t *testing.T) {
		options := CORSOptions{
			AllowedOrigins: []string{"https://example.com"},
			AllowedMethods: []string{},
			AllowedHeaders: []string{"Content-Type"},
		}

		handler := CORSMiddleware(options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, "", rec.Header().Get("Access-Control-Allow-Methods"))
	})

	t.Run("handles empty headers list", func(t *testing.T) {
		options := CORSOptions{
			AllowedOrigins: []string{"https://example.com"},
			AllowedMethods: []string{"GET"},
			AllowedHeaders: []string{},
		}

		handler := CORSMiddleware(options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, "", rec.Header().Get("Access-Control-Allow-Headers"))
	})
}

func TestIsAllowedOrigin(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		allowedOrigins []string
		expected       bool
	}{
		{
			name:           "exact match",
			origin:         "https://example.com",
			allowedOrigins: []string{"https://example.com"},
			expected:       true,
		},
		{
			name:           "wildcard allows all",
			origin:         "https://any-domain.com",
			allowedOrigins: []string{"*"},
			expected:       true,
		},
		{
			name:           "not in list",
			origin:         "https://malicious.com",
			allowedOrigins: []string{"https://example.com", "https://example.org"},
			expected:       false,
		},
		{
			name:           "empty allowed origins",
			origin:         "https://example.com",
			allowedOrigins: []string{},
			expected:       false,
		},
		{
			name:           "nil allowed origins",
			origin:         "https://example.com",
			allowedOrigins: nil,
			expected:       false,
		},
		{
			name:           "empty origin",
			origin:         "",
			allowedOrigins: []string{"https://example.com"},
			expected:       false,
		},
		{
			name:           "wildcard in list",
			origin:         "https://example.com",
			allowedOrigins: []string{"https://other.com", "*"},
			expected:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAllowedOrigin(tt.origin, tt.allowedOrigins)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJoin(t *testing.T) {
	tests := []struct {
		name      string
		strings   []string
		separator string
		expected  string
	}{
		{
			name:      "join with comma",
			strings:   []string{"a", "b", "c"},
			separator: ", ",
			expected:  "a, b, c",
		},
		{
			name:      "join single element",
			strings:   []string{"single"},
			separator: ", ",
			expected:  "single",
		},
		{
			name:      "join empty list",
			strings:   []string{},
			separator: ", ",
			expected:  "",
		},
		{
			name:      "join with different separator",
			strings:   []string{"GET", "POST", "PUT"},
			separator: "|",
			expected:  "GET|POST|PUT",
		},
		{
			name:      "join with empty separator",
			strings:   []string{"a", "b", "c"},
			separator: "",
			expected:  "abc",
		},
		{
			name:      "join two elements",
			strings:   []string{"first", "second"},
			separator: " - ",
			expected:  "first - second",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := join(tt.strings, tt.separator)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCORSMiddlewareIntegration(t *testing.T) {
	t.Run("full request flow with CORS", func(t *testing.T) {
		options := CORSOptions{
			AllowedOrigins:   []string{"https://app.example.com"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
			AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Custom-Header"},
			AllowCredentials: true,
		}

		handlerCalled := false
		handler := CORSMiddleware(options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.Header().Set("X-Custom-Response", "test")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"status": "created"}`))
		}))

		req := httptest.NewRequest(http.MethodPost, "/api/resource", nil)
		req.Header.Set("Origin", "https://app.example.com")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.True(t, handlerCalled)
		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Equal(t, "https://app.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST, PUT, DELETE", rec.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Content-Type, Authorization, X-Custom-Header", rec.Header().Get("Access-Control-Allow-Headers"))
		assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "test", rec.Header().Get("X-Custom-Response"))
		assert.Equal(t, `{"status": "created"}`, rec.Body.String())
	})
}
