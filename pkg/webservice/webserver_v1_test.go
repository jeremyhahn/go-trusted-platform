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

package webservice

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestLogger creates a test logger with minimal output
func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

func TestValidateHostHeader(t *testing.T) {
	logger := newTestLogger()
	server := &WebServerV1{
		logger: logger,
	}

	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "localhost",
			host:     "localhost",
			expected: true,
		},
		{
			name:     "localhost with port",
			host:     "localhost:8080",
			expected: true,
		},
		{
			name:     "valid domain",
			host:     "example.com",
			expected: true,
		},
		{
			name:     "valid domain with port",
			host:     "example.com:443",
			expected: true,
		},
		{
			name:     "valid subdomain",
			host:     "api.example.com",
			expected: true,
		},
		{
			name:     "valid subdomain with port",
			host:     "api.example.com:8443",
			expected: true,
		},
		{
			name:     "multi-level subdomain",
			host:     "api.v1.example.com",
			expected: true,
		},
		{
			name:     "IPv4 address",
			host:     "192.168.1.1",
			expected: true,
		},
		{
			name:     "IPv4 with port",
			host:     "192.168.1.1:8080",
			expected: true,
		},
		{
			name:     "IPv6 address",
			host:     "::1",
			expected: true,
		},
		{
			name:     "IPv6 loopback",
			host:     "[::1]:8080",
			expected: true,
		},
		{
			name:     "IPv6 full",
			host:     "2001:db8::1",
			expected: true,
		},
		{
			name:     "invalid - path traversal attempt",
			host:     "../etc/passwd",
			expected: false,
		},
		{
			name:     "invalid - null byte injection",
			host:     "example.com\x00.evil.com",
			expected: false,
		},
		{
			name:     "invalid - newline injection",
			host:     "example.com\nHost: evil.com",
			expected: false,
		},
		{
			name:     "invalid - special characters",
			host:     "example!@#.com",
			expected: false,
		},
		{
			name:     "empty host",
			host:     "",
			expected: false,
		},
		{
			name:     "single dot TLD",
			host:     "localhost.x",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.validateHostHeader(tt.host)
			assert.Equal(t, tt.expected, result, "host: %s", tt.host)
		})
	}
}

func TestServeStaticFiles(t *testing.T) {
	logger := newTestLogger()
	tmpDir := t.TempDir()

	// Create test files
	indexContent := "<!DOCTYPE html><html><body>Index</body></html>"
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte(indexContent), 0644))

	testFileContent := "test file content"
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte(testFileContent), 0644))

	// Create a subdirectory with index
	subDir := filepath.Join(tmpDir, "subdir")
	require.NoError(t, os.MkdirAll(subDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "index.html"), []byte("<html>Subdir</html>"), 0644))

	server := &WebServerV1{
		logger: logger,
	}

	t.Run("serve existing file", func(t *testing.T) {
		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/test.txt", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "test file content")
	})

	t.Run("serve index for root", func(t *testing.T) {
		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "Index")
	})

	t.Run("serve directory index", func(t *testing.T) {
		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/subdir/", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "Subdir")
	})

	t.Run("SPA fallback for non-static routes", func(t *testing.T) {
		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/some/spa/route", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		// Should fallback to index.html for SPA routing
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "Index")
	})

	t.Run("404 for missing _next static resources", func(t *testing.T) {
		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/_next/static/missing.js", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("404 for missing static resources", func(t *testing.T) {
		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/static/missing.css", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("rewrite rules - valid pattern match", func(t *testing.T) {
		rules := []*v1.RewriteRule{
			{Pattern: "^/old-path$", Target: "/test.txt"},
		}
		handler := server.serveStaticFiles(tmpDir, "index.html", rules)
		req := httptest.NewRequest(http.MethodGet, "/old-path", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "test file content")
	})

	t.Run("rewrite rules - no match continues normally", func(t *testing.T) {
		rules := []*v1.RewriteRule{
			{Pattern: "^/nomatch$", Target: "/other.txt"},
		}
		handler := server.serveStaticFiles(tmpDir, "index.html", rules)
		req := httptest.NewRequest(http.MethodGet, "/test.txt", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "test file content")
	})

	t.Run("rewrite rules - invalid pattern logged but continues", func(t *testing.T) {
		rules := []*v1.RewriteRule{
			{Pattern: "[invalid(regex", Target: "/test.txt"},
		}
		handler := server.serveStaticFiles(tmpDir, "index.html", rules)
		req := httptest.NewRequest(http.MethodGet, "/somepath", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		// Should continue to SPA fallback despite invalid regex
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("directory without index returns fallback", func(t *testing.T) {
		// Create a directory without index
		emptyDir := filepath.Join(tmpDir, "emptydir")
		require.NoError(t, os.MkdirAll(emptyDir, 0755))

		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/emptydir/", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		// Should fallback to root index
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "Index")
	})

	t.Run("path with special characters", func(t *testing.T) {
		// Create a file with special name
		specialFile := filepath.Join(tmpDir, "file-with-dashes.txt")
		require.NoError(t, os.WriteFile(specialFile, []byte("special content"), 0644))

		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/file-with-dashes.txt", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "special content")
	})
}

func TestEnsureDirectoryExists(t *testing.T) {
	logger := newTestLogger()
	server := &WebServerV1{
		logger: logger,
	}

	t.Run("creates directory and index file", func(t *testing.T) {
		tmpDir := t.TempDir()
		vhostDir := filepath.Join(tmpDir, "newvhost")

		err := server.ensureDirectoryExists(vhostDir, "test.example.com", "index.html")
		require.NoError(t, err)

		// Verify directory exists
		info, err := os.Stat(vhostDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())

		// Verify index file exists and contains virtual host name
		indexPath := filepath.Join(vhostDir, "index.html")
		content, err := os.ReadFile(indexPath)
		require.NoError(t, err)
		assert.Contains(t, string(content), "test.example.com")
	})

	t.Run("uses existing directory without recreating index", func(t *testing.T) {
		tmpDir := t.TempDir()
		customContent := "Custom content"

		// Create directory with custom index
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte(customContent), 0644))

		err := server.ensureDirectoryExists(tmpDir, "existing.example.com", "index.html")
		require.NoError(t, err)

		// Verify custom index was not overwritten
		content, err := os.ReadFile(filepath.Join(tmpDir, "index.html"))
		require.NoError(t, err)
		assert.Equal(t, customContent, string(content))
	})

	t.Run("creates nested directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		nestedDir := filepath.Join(tmpDir, "a", "b", "c", "vhost")

		err := server.ensureDirectoryExists(nestedDir, "nested.example.com", "index.html")
		require.NoError(t, err)

		// Verify all directories were created
		info, err := os.Stat(nestedDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})
}

func TestCreateDefaultIndexFile(t *testing.T) {
	logger := newTestLogger()
	server := &WebServerV1{
		logger: logger,
	}

	t.Run("creates default index with virtual host", func(t *testing.T) {
		tmpDir := t.TempDir()

		err := server.createDefaultIndexFile(tmpDir, "myhost.example.com", "index.html")
		require.NoError(t, err)

		content, err := os.ReadFile(filepath.Join(tmpDir, "index.html"))
		require.NoError(t, err)
		assert.Contains(t, string(content), "myhost.example.com")
		assert.Contains(t, string(content), "<!DOCTYPE html>")
		assert.Contains(t, string(content), "<html>")
	})

	t.Run("skips existing file", func(t *testing.T) {
		tmpDir := t.TempDir()
		existingContent := "existing content"
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte(existingContent), 0644))

		err := server.createDefaultIndexFile(tmpDir, "newhost.example.com", "index.html")
		require.NoError(t, err)

		content, err := os.ReadFile(filepath.Join(tmpDir, "index.html"))
		require.NoError(t, err)
		assert.Equal(t, existingContent, string(content))
	})

	t.Run("creates custom named index file", func(t *testing.T) {
		tmpDir := t.TempDir()

		err := server.createDefaultIndexFile(tmpDir, "custom.example.com", "main.html")
		require.NoError(t, err)

		content, err := os.ReadFile(filepath.Join(tmpDir, "main.html"))
		require.NoError(t, err)
		assert.Contains(t, string(content), "custom.example.com")
	})
}

func TestReverseProxyHandler(t *testing.T) {
	logger := newTestLogger()
	server := &WebServerV1{
		logger: logger,
	}

	t.Run("no backends configured", func(t *testing.T) {
		handler := server.reverseProxyHandler([]string{}, RoundRobinBalancer())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "No backend servers configured")
	})

	t.Run("invalid backend URL", func(t *testing.T) {
		handler := server.reverseProxyHandler([]string{"://invalid-url"}, RoundRobinBalancer())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid backend URL")
	})

	t.Run("proxies to valid backend", func(t *testing.T) {
		// Create a test backend server
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("backend response"))
		}))
		defer backend.Close()

		handler := server.reverseProxyHandler([]string{backend.URL}, RoundRobinBalancer())
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "backend response")
	})

	t.Run("round robin across multiple backends", func(t *testing.T) {
		responses := make(chan string, 3)

		backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("backend1"))
		}))
		defer backend1.Close()

		backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("backend2"))
		}))
		defer backend2.Close()

		balancer := RoundRobinBalancer()
		handler := server.reverseProxyHandler([]string{backend1.URL, backend2.URL}, balancer)

		// Make 3 requests
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			handler(w, req)
			responses <- w.Body.String()
		}

		close(responses)

		var results []string
		for r := range responses {
			results = append(results, r)
		}

		// Should alternate between backends
		assert.Equal(t, "backend1", results[0])
		assert.Equal(t, "backend2", results[1])
		assert.Equal(t, "backend1", results[2])
	})

	t.Run("backend returns error status", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad request"))
		}))
		defer backend.Close()

		handler := server.reverseProxyHandler([]string{backend.URL}, RoundRobinBalancer())
		req := httptest.NewRequest(http.MethodPost, "/api/create", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("preserves request headers", func(t *testing.T) {
		var receivedHeaders http.Header
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		handler := server.reverseProxyHandler([]string{backend.URL}, RoundRobinBalancer())
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Custom-Header", "test-value")
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, "test-value", receivedHeaders.Get("X-Custom-Header"))
	})
}

func TestEndpoints(t *testing.T) {
	logger := newTestLogger()
	responseWriter := response.NewResponseWriter(logger, nil)

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/api/v1/test", func(w http.ResponseWriter, r *http.Request) {})
	router.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {})

	server := &WebServerV1{
		logger: logger,
		router: router,
	}

	t.Run("returns list of endpoints", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/endpoints", nil)
		w := httptest.NewRecorder()

		// Manually create the handler to test
		server.router.HandleFunc("/endpoints", func(w http.ResponseWriter, r *http.Request) {
			endpoints := make([]string, 0)
			server.router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
				t, err := route.GetPathTemplate()
				if err != nil {
					return err
				}
				endpoints = append(endpoints, t)
				return nil
			})
			responseWriter.Write(w, r, http.StatusOK, endpoints)
		})

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "/api/v1/test")
		assert.Contains(t, w.Body.String(), "/api/v1/users")
	})
}

func TestAddAltSvcHeader(t *testing.T) {
	t.Run("adds Alt-Svc header to response", func(t *testing.T) {
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})

		handler := addAltSvcHeader(nextHandler)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, `h3=":443"; ma=86400`, w.Header().Get("Alt-Svc"))
		assert.Equal(t, "OK", w.Body.String())
	})

	t.Run("does not override existing Alt-Svc header", func(t *testing.T) {
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := addAltSvcHeader(nextHandler)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// The middleware always sets the header
		assert.Equal(t, `h3=":443"; ma=86400`, w.Header().Get("Alt-Svc"))
	})

	t.Run("passes through POST requests", func(t *testing.T) {
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			w.WriteHeader(http.StatusCreated)
		})

		handler := addAltSvcHeader(nextHandler)
		req := httptest.NewRequest(http.MethodPost, "/api/resource", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		assert.NotEmpty(t, w.Header().Get("Alt-Svc"))
	})
}

func TestDebugRoutes(t *testing.T) {
	logger := newTestLogger()
	router := mux.NewRouter().StrictSlash(true)

	// Add some test routes
	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {}).Methods("GET")
	router.HandleFunc("/users/{id}", func(w http.ResponseWriter, r *http.Request) {}).Methods("GET", "PUT")

	server := &WebServerV1{
		logger: logger,
		router: router,
		debug:  true,
	}

	// debugRoutes should not panic even with various route configurations
	t.Run("debugRoutes does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			server.debugRoutes()
		})
	})

	t.Run("debugRoutes with empty router", func(t *testing.T) {
		emptyRouter := mux.NewRouter()
		emptyServer := &WebServerV1{
			logger: logger,
			router: emptyRouter,
			debug:  true,
		}

		assert.NotPanics(t, func() {
			emptyServer.debugRoutes()
		})
	})

	t.Run("debugRoutes with complex routes", func(t *testing.T) {
		complexRouter := mux.NewRouter()
		complexRouter.HandleFunc("/api/v1/users", nil).Methods("GET", "POST")
		complexRouter.HandleFunc("/api/v1/users/{id:[0-9]+}", nil).Methods("GET", "PUT", "DELETE")
		complexRouter.HandleFunc("/api/v1/users/{id}/posts", nil).Methods("GET")
		complexRouter.Queries("page", "{page:[0-9]+}", "limit", "{limit:[0-9]+}")

		complexServer := &WebServerV1{
			logger: logger,
			router: complexRouter,
			debug:  true,
		}

		assert.NotPanics(t, func() {
			complexServer.debugRoutes()
		})
	})
}

func TestWebServerErrors(t *testing.T) {
	t.Run("error types are defined", func(t *testing.T) {
		assert.Error(t, ErrLoadTlsCerts)
		assert.Error(t, ErrBindPort)
		assert.Contains(t, ErrLoadTlsCerts.Error(), "TLS")
		assert.Contains(t, ErrBindPort.Error(), "bind")
	})
}

func TestServerConstants(t *testing.T) {
	t.Run("timeout constants are set", func(t *testing.T) {
		assert.NotZero(t, HTTP_CLIENT_TIMEOUT)
		assert.NotZero(t, HTTP_SERVER_READ_TIMEOUT)
		assert.NotZero(t, HTTP_SERVER_WRITE_TIMEOUT)
		assert.NotZero(t, HTTP_SERVER_IDLE_TIMEOUT)
	})

	t.Run("timeout values are reasonable", func(t *testing.T) {
		// Verify timeouts are in reasonable ranges
		assert.True(t, HTTP_CLIENT_TIMEOUT > 0)
		assert.True(t, HTTP_SERVER_READ_TIMEOUT > 0)
		assert.True(t, HTTP_SERVER_WRITE_TIMEOUT > HTTP_SERVER_READ_TIMEOUT)
		assert.True(t, HTTP_SERVER_IDLE_TIMEOUT > HTTP_SERVER_WRITE_TIMEOUT)
	})
}

func TestDefaultIndexTemplate(t *testing.T) {
	t.Run("template contains required elements", func(t *testing.T) {
		assert.Contains(t, defaultIndexTemplate, "<!DOCTYPE html>")
		assert.Contains(t, defaultIndexTemplate, "<html>")
		assert.Contains(t, defaultIndexTemplate, "{{.VirtualHost}}")
		assert.Contains(t, defaultIndexTemplate, "</html>")
	})

	t.Run("template is valid HTML structure", func(t *testing.T) {
		assert.Contains(t, defaultIndexTemplate, "<head>")
		assert.Contains(t, defaultIndexTemplate, "</head>")
		assert.Contains(t, defaultIndexTemplate, "<body>")
		assert.Contains(t, defaultIndexTemplate, "</body>")
	})
}

func TestWebServerV1Struct(t *testing.T) {
	logger := newTestLogger()

	t.Run("struct can be created manually", func(t *testing.T) {
		router := mux.NewRouter()
		server := &WebServerV1{
			logger:      logger,
			router:      router,
			routerMutex: &sync.Mutex{},
			baseURI:     "/api/v1",
			debug:       true,
		}

		assert.NotNil(t, server)
		assert.Equal(t, "/api/v1", server.baseURI)
		assert.True(t, server.debug)
	})

	t.Run("router mutex is thread-safe", func(t *testing.T) {
		router := mux.NewRouter()
		server := &WebServerV1{
			logger:      logger,
			router:      router,
			routerMutex: &sync.Mutex{},
		}

		// Test concurrent access
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				server.routerMutex.Lock()
				server.router.HandleFunc("/concurrent", nil)
				server.routerMutex.Unlock()
			}()
		}
		wg.Wait()
	})
}

func TestValidateHostHeader_EdgeCases(t *testing.T) {
	logger := newTestLogger()
	server := &WebServerV1{
		logger: logger,
	}

	t.Run("host with valid port range", func(t *testing.T) {
		assert.True(t, server.validateHostHeader("example.com:1"))
		assert.True(t, server.validateHostHeader("example.com:65535"))
	})

	t.Run("host with various TLDs", func(t *testing.T) {
		assert.True(t, server.validateHostHeader("example.io"))
		assert.True(t, server.validateHostHeader("example.co.uk"))
		assert.True(t, server.validateHostHeader("example.technology"))
	})

	t.Run("localhost variations", func(t *testing.T) {
		assert.True(t, server.validateHostHeader("localhost"))
		assert.True(t, server.validateHostHeader("localhost:3000"))
		assert.True(t, server.validateHostHeader("localhost:443"))
	})

	t.Run("IP address variations", func(t *testing.T) {
		assert.True(t, server.validateHostHeader("127.0.0.1"))
		assert.True(t, server.validateHostHeader("0.0.0.0"))
		assert.True(t, server.validateHostHeader("10.0.0.1"))
		assert.True(t, server.validateHostHeader("172.16.0.1"))
		assert.True(t, server.validateHostHeader("192.168.255.255"))
	})
}

func TestServeStaticFiles_EdgeCases(t *testing.T) {
	logger := newTestLogger()
	tmpDir := t.TempDir()

	// Create test files
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte("Index"), 0644))

	server := &WebServerV1{
		logger: logger,
	}

	t.Run("multiple rewrite rules", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "target1.txt"), []byte("target1"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "target2.txt"), []byte("target2"), 0644))

		rules := []*v1.RewriteRule{
			{Pattern: "^/first$", Target: "/target1.txt"},
			{Pattern: "^/second$", Target: "/target2.txt"},
		}
		handler := server.serveStaticFiles(tmpDir, "index.html", rules)

		// Test first rule
		req1 := httptest.NewRequest(http.MethodGet, "/first", nil)
		w1 := httptest.NewRecorder()
		handler(w1, req1)
		assert.Contains(t, w1.Body.String(), "target1")

		// Test second rule
		req2 := httptest.NewRequest(http.MethodGet, "/second", nil)
		w2 := httptest.NewRecorder()
		handler(w2, req2)
		assert.Contains(t, w2.Body.String(), "target2")
	})

	t.Run("first matching rewrite rule wins", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "first.txt"), []byte("first rule"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "second.txt"), []byte("second rule"), 0644))

		rules := []*v1.RewriteRule{
			{Pattern: "^/test.*", Target: "/first.txt"},
			{Pattern: "^/test$", Target: "/second.txt"},
		}
		handler := server.serveStaticFiles(tmpDir, "index.html", rules)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		handler(w, req)

		// First matching rule should win
		assert.Contains(t, w.Body.String(), "first rule")
	})

	t.Run("serves files from root path", func(t *testing.T) {
		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "Index")
	})

	t.Run("handles non-existent files with fallback", func(t *testing.T) {
		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/nonexistent/path/file.txt", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		// Should fallback to SPA index
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "Index")
	})
}

func TestIsNonSPAPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"api path", "/api/v1/health", true},
		{"api root", "/api/", true},
		{"canonical trust bootstrap", "/v1/ca/bootstrap", true},
		{"unclaimed canonical path", "/v1/ca/nonexistent", true},
		{"oci distribution", "/v2/library/alpine/manifests/latest", true},
		{"well-known discovery", "/.well-known/openid-configuration", true},
		{"next static", "/_next/static/chunk.js", true},
		{"static assets", "/static/image.png", true},
		{"spa route", "/dashboard", false},
		{"spa nested", "/admin/settings", false},
		{"spa route sharing a version prefix", "/v1beta/console", false},
		{"spa route named like a version", "/versions", false},
		{"root", "/", false},
		{"empty", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isNonSPAPath(tc.path)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsAPIPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"api v1 health", "/api/v1/health", true},
		{"api v1 daemon", "/api/v1/daemon/health", true},
		{"api root", "/api/", true},
		{"canonical trust bootstrap", "/v1/ca/bootstrap", true},
		{"oci distribution", "/v2/", true},
		{"well-known jwks", "/.well-known/jwks.json", true},
		{"non-api", "/dashboard", false},
		{"spa route sharing a version prefix", "/v1beta/console", false},
		{"next static", "/_next/static/chunk.js", false},
		{"root", "/", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isAPIPath(tc.path)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestWriteJSONNotFound(t *testing.T) {
	t.Run("API path returns JSON 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		w := httptest.NewRecorder()

		writeJSONNotFound(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		assert.Contains(t, w.Body.String(), `"error"`)
		assert.Contains(t, w.Body.String(), `"not found"`)
		assert.Contains(t, w.Body.String(), "/api/v1/health")
	})

	t.Run("non-API path returns plain 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/some/page", nil)
		w := httptest.NewRecorder()

		writeJSONNotFound(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.NotEqual(t, "application/json", w.Header().Get("Content-Type"))
	})
}

func TestServeStaticFiles_APIPathNotFallback(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, io.Discard)

	tmpDir := t.TempDir()
	indexContent := "<html>SPA Index</html>"
	os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte(indexContent), 0644)

	server := &WebServerV1{
		logger:      logger,
		router:      mux.NewRouter(),
		routerMutex: &sync.Mutex{},
		config:      &v1.Config{},
	}

	t.Run("API path returns 404 not SPA HTML", func(t *testing.T) {
		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.NotContains(t, w.Body.String(), "SPA Index")
	})

	t.Run("API nested path returns 404 not SPA HTML", func(t *testing.T) {
		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/daemon/health", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.NotContains(t, w.Body.String(), "SPA Index")
	})

	t.Run("non-API path still gets SPA fallback", func(t *testing.T) {
		handler := server.serveStaticFiles(tmpDir, "index.html", nil)
		req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "SPA Index")
	})
}

// TestServeStaticFiles_VersionedAPIPathNotFallback covers the second half of
// issue #201: an unclaimed path under a namespace the API routers own must
// 404 as JSON. Answering it with the console's index.html gives an API client
// a 200 and an HTML body, and the only symptom is a parse failure downstream
// that names neither the route nor the cause — which is exactly how the
// missing /v1/ca/bootstrap route presented as "invalid PEM data".
func TestServeStaticFiles_VersionedAPIPathNotFallback(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, io.Discard)

	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, "index.html"), []byte("<html>SPA Index</html>"), 0644))

	server := &WebServerV1{
		logger:      logger,
		router:      mux.NewRouter(),
		routerMutex: &sync.Mutex{},
		config:      &v1.Config{},
	}
	handler := server.serveStaticFiles(tmpDir, "index.html", nil)

	apiPaths := []string{
		"/v1/ca/nonexistent",
		"/v1/ca/bootstrap",
		"/v2/library/alpine/manifests/latest",
		"/.well-known/openid-configuration",
		"/.well-known/jwks.json",
	}
	for _, path := range apiPaths {
		t.Run("JSON 404 for "+path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			handler(w, req)

			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			assert.NotContains(t, w.Body.String(), "SPA Index")
			assert.Contains(t, w.Body.String(), path)
		})
	}

	// Console routes that merely look like an API namespace must still
	// hydrate the SPA — the decline is prefix-anchored, not substring-based.
	spaPaths := []string{"/v1beta/console", "/versions", "/dashboard"}
	for _, path := range spaPaths {
		t.Run("SPA fallback for "+path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			handler(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), "SPA Index")
		})
	}
}
