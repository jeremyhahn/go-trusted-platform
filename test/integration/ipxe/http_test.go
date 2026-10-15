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

//go:build integration

package ipxe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// HTTP Boot Script Tests
// =============================================================================

// TestHTTPBootScript tests fetching the initial boot script.
func TestHTTPBootScript(t *testing.T) {
	ctx, cancel := HTTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	baseURL := fmt.Sprintf("http://%s:%d", cfg.ServerIP, cfg.HTTPPort)

	t.Run("GetBootScript", func(t *testing.T) {
		resp, body, err := httpGet(ctx, baseURL+"/boot.ipxe")
		require.NoError(t, err, "GET /boot.ipxe should succeed")
		require.Equal(t, http.StatusOK, resp.StatusCode, "Should return 200 OK")

		// Verify it is an iPXE script
		assert.True(t, strings.HasPrefix(body, "#!ipxe"), "Script should start with #!ipxe shebang")

		// Verify it chains to the menu
		assert.Contains(t, body, "chain", "Script should chain to menu")
		assert.Contains(t, body, "menu.ipxe", "Script should reference menu.ipxe")
	})

	t.Run("BootScriptContentType", func(t *testing.T) {
		resp, _, err := httpGet(ctx, baseURL+"/boot.ipxe")
		require.NoError(t, err, "GET /boot.ipxe should succeed")

		contentType := resp.Header.Get("Content-Type")
		assert.True(t,
			strings.Contains(contentType, "text/plain") ||
				strings.Contains(contentType, "application/octet-stream"),
			"Content-Type should be text/plain or octet-stream")
	})
}

// TestHTTPMenuScript tests fetching the boot menu script.
func TestHTTPMenuScript(t *testing.T) {
	ctx, cancel := HTTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	baseURL := fmt.Sprintf("http://%s:%d", cfg.ServerIP, cfg.HTTPPort)

	t.Run("GetMenuScript", func(t *testing.T) {
		resp, body, err := httpGet(ctx, baseURL+"/menu.ipxe")
		require.NoError(t, err, "GET /menu.ipxe should succeed")
		require.Equal(t, http.StatusOK, resp.StatusCode, "Should return 200 OK")

		// Verify it is an iPXE script
		assert.True(t, strings.HasPrefix(body, "#!ipxe"), "Menu should start with #!ipxe shebang")

		// Verify menu structure
		assert.Contains(t, body, "menu", "Should contain menu command")
		assert.Contains(t, body, "item", "Should contain menu items")
		assert.Contains(t, body, "choose", "Should contain choose command")
	})

	t.Run("MenuContainsBootEntries", func(t *testing.T) {
		_, body, err := httpGet(ctx, baseURL+"/menu.ipxe")
		require.NoError(t, err, "GET /menu.ipxe should succeed")

		// Menu should contain at least shell and reboot options
		assert.Contains(t, body, "shell", "Menu should have shell option")
		assert.Contains(t, body, "reboot", "Menu should have reboot option")
	})

	t.Run("MenuContainsUtilities", func(t *testing.T) {
		_, body, err := httpGet(ctx, baseURL+"/menu.ipxe")
		require.NoError(t, err, "GET /menu.ipxe should succeed")

		// Verify utility entries
		assert.Contains(t, body, ":shell", "Menu should have shell label")
		assert.Contains(t, body, ":reboot", "Menu should have reboot label")
	})
}

// TestHTTPBootEntries tests fetching individual boot entry scripts.
func TestHTTPBootEntries(t *testing.T) {
	ctx, cancel := HTTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	baseURL := fmt.Sprintf("http://%s:%d", cfg.ServerIP, cfg.HTTPPort)

	// First, get the menu to find available entries
	_, menuBody, err := httpGet(ctx, baseURL+"/menu.ipxe")
	require.NoError(t, err, "GET /menu.ipxe should succeed")

	// Extract boot entry names from menu
	entryNames := extractBootEntryNames(menuBody)

	for _, entryName := range entryNames {
		entryName := entryName // capture
		t.Run("BootEntry_"+entryName, func(t *testing.T) {
			entryURL := fmt.Sprintf("%s/boot/%s.ipxe", baseURL, entryName)
			resp, body, err := httpGet(ctx, entryURL)
			require.NoError(t, err, "GET %s should succeed", entryURL)
			require.Equal(t, http.StatusOK, resp.StatusCode, "Should return 200 OK")

			// Verify it is an iPXE script
			assert.True(t, strings.HasPrefix(body, "#!ipxe"),
				"Boot entry should start with #!ipxe shebang")

			// Verify boot commands are present
			hasKernel := strings.Contains(body, "kernel")
			hasChain := strings.Contains(body, "chain")
			hasBoot := strings.Contains(body, "boot")

			assert.True(t, hasKernel || hasChain,
				"Boot entry should have kernel or chain command")
			assert.True(t, hasBoot || hasChain,
				"Boot entry should have boot or chain command")
		})
	}
}

// TestHTTPBootEntryNotFound tests handling of non-existent boot entries.
func TestHTTPBootEntryNotFound(t *testing.T) {
	ctx, cancel := HTTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	baseURL := fmt.Sprintf("http://%s:%d", cfg.ServerIP, cfg.HTTPPort)

	t.Run("NonExistentEntry", func(t *testing.T) {
		resp, _, err := httpGet(ctx, baseURL+"/boot/nonexistent-entry.ipxe")
		require.NoError(t, err, "Request should complete")
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "Should return 404")
	})
}

// TestHTTPHealthCheck tests the health check endpoint.
func TestHTTPHealthCheck(t *testing.T) {
	ctx, cancel := HTTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	baseURL := fmt.Sprintf("http://%s:%d", cfg.ServerIP, cfg.HTTPPort)

	t.Run("HealthEndpoint", func(t *testing.T) {
		resp, body, err := httpGet(ctx, baseURL+"/health")
		require.NoError(t, err, "GET /health should succeed")
		require.Equal(t, http.StatusOK, resp.StatusCode, "Should return 200 OK")

		// Parse JSON response
		var health struct {
			Status string `json:"status"`
		}
		err = json.Unmarshal([]byte(body), &health)
		require.NoError(t, err, "Response should be valid JSON")

		assert.Equal(t, "healthy", health.Status, "Status should be healthy")
	})

	t.Run("HealthContentType", func(t *testing.T) {
		resp, _, err := httpGet(ctx, baseURL+"/health")
		require.NoError(t, err, "GET /health should succeed")

		contentType := resp.Header.Get("Content-Type")
		assert.Contains(t, contentType, "application/json", "Content-Type should be JSON")
	})
}

// TestHTTPProxy tests the HTTPS proxy endpoint.
func TestHTTPProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := GetTestServerConfig()
	baseURL := fmt.Sprintf("http://%s:%d", cfg.ServerIP, cfg.HTTPPort)

	t.Run("ProxyHTTPSResource", func(t *testing.T) {
		// Proxy a small HTTPS resource
		proxyURL := baseURL + "/proxy/https/httpbin.org/get"
		resp, body, err := httpGet(ctx, proxyURL)
		require.NoError(t, err, "Request to the test iPXE server should complete")

		assert.Equal(t, http.StatusOK, resp.StatusCode, "Proxy should return 200")
		assert.NotEmpty(t, body, "Response body should not be empty")
	})

	t.Run("ProxyRejectHTTP", func(t *testing.T) {
		// Only HTTPS should be proxied
		proxyURL := baseURL + "/proxy/http/example.com/"
		resp, _, err := httpGet(ctx, proxyURL)
		require.NoError(t, err, "Request should complete")

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"Non-HTTPS proxy should be rejected")
	})

	t.Run("ProxyInvalidURL", func(t *testing.T) {
		proxyURL := baseURL + "/proxy/"
		resp, _, err := httpGet(ctx, proxyURL)
		require.NoError(t, err, "Request should complete")

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"Invalid proxy URL should return 400")
	})
}

// TestHTTPStaticFiles tests serving static files.
func TestHTTPStaticFiles(t *testing.T) {
	ctx, cancel := HTTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	baseURL := fmt.Sprintf("http://%s:%d", cfg.ServerIP, cfg.HTTPPort)

	t.Run("PathTraversalBlocked", func(t *testing.T) {
		resp, _, err := httpGet(ctx, baseURL+"/static/../../../etc/passwd")
		require.NoError(t, err, "Request should complete")

		// Should either return 400 Bad Request or 404 Not Found
		assert.True(t,
			resp.StatusCode == http.StatusBadRequest ||
				resp.StatusCode == http.StatusNotFound,
			"Path traversal should be blocked")
	})

	t.Run("DirectoryListingBlocked", func(t *testing.T) {
		resp, _, err := httpGet(ctx, baseURL+"/static/")
		require.NoError(t, err, "Request should complete")

		// Directory listing should be blocked or return 404
		assert.True(t,
			resp.StatusCode == http.StatusForbidden ||
				resp.StatusCode == http.StatusNotFound,
			"Directory listing should be blocked")
	})
}

// TestHTTPLocalFiles tests the local files endpoint.
func TestHTTPLocalFiles(t *testing.T) {
	ctx, cancel := HTTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	baseURL := fmt.Sprintf("http://%s:%d", cfg.ServerIP, cfg.HTTPPort)

	t.Run("PathTraversalBlocked", func(t *testing.T) {
		resp, _, err := httpGet(ctx, baseURL+"/files/../../../etc/passwd")
		require.NoError(t, err, "Request should complete")

		assert.True(t,
			resp.StatusCode == http.StatusBadRequest ||
				resp.StatusCode == http.StatusNotFound,
			"Path traversal should be blocked")
	})

	t.Run("EmptyPathRejected", func(t *testing.T) {
		resp, _, err := httpGet(ctx, baseURL+"/files/")
		require.NoError(t, err, "Request should complete")

		assert.True(t,
			resp.StatusCode == http.StatusBadRequest ||
				resp.StatusCode == http.StatusNotFound ||
				resp.StatusCode == http.StatusForbidden,
			"Empty path should be rejected")
	})
}

// TestHTTPConcurrentRequests tests handling concurrent HTTP requests.
func TestHTTPConcurrentRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := GetTestServerConfig()
	baseURL := fmt.Sprintf("http://%s:%d", cfg.ServerIP, cfg.HTTPPort)
	numClients := 10

	t.Run("ParallelBootScriptRequests", func(t *testing.T) {
		type result struct {
			clientID   int
			statusCode int
			err        error
		}

		results := make(chan result, numClients)

		// Send concurrent requests
		for i := 0; i < numClients; i++ {
			go func(id int) {
				resp, _, err := httpGet(ctx, baseURL+"/boot.ipxe")
				var statusCode int
				if resp != nil {
					statusCode = resp.StatusCode
				}
				results <- result{clientID: id, statusCode: statusCode, err: err}
			}(i)
		}

		// Collect results
		successCount := 0
		for i := 0; i < numClients; i++ {
			r := <-results
			if r.err != nil {
				t.Errorf("Client %d failed: %v", r.clientID, r.err)
				continue
			}
			if r.statusCode == http.StatusOK {
				successCount++
			}
		}

		assert.Equal(t, numClients, successCount, "All requests should succeed")
	})
}

// =============================================================================
// HTTP Error Scenario Tests
// =============================================================================

// TestHTTPErrorScenarios tests various HTTP error conditions.
func TestHTTPErrorScenarios(t *testing.T) {
	cfg := GetTestServerConfig()
	baseURL := fmt.Sprintf("http://%s:%d", cfg.ServerIP, cfg.HTTPPort)

	t.Run("MethodNotAllowed", func(t *testing.T) {
		ctx, cancel := HTTPTestContext()
		defer cancel()

		// POST to boot.ipxe should not be allowed
		resp, err := httpPost(ctx, baseURL+"/boot.ipxe", "")
		require.NoError(t, err, "Request should complete")

		// Should return 405 Method Not Allowed or be handled gracefully
		assert.True(t,
			resp.StatusCode == http.StatusMethodNotAllowed ||
				resp.StatusCode == http.StatusOK,
			"POST should be rejected or handled")
	})

	t.Run("InvalidPaths", func(t *testing.T) {
		ctx, cancel := HTTPTestContext()
		defer cancel()

		invalidPaths := []string{
			"/nonexistent",
			"/boot/",
			"/../../../",
		}

		for _, path := range invalidPaths {
			resp, _, err := httpGet(ctx, baseURL+path)
			require.NoError(t, err, "Request to %s should complete", path)
			assert.True(t,
				resp.StatusCode == http.StatusNotFound ||
					resp.StatusCode == http.StatusBadRequest,
				"Invalid path %s should return 404 or 400", path)
		}
	})
}

// =============================================================================
// HTTP Helper Functions
// =============================================================================

// httpGet performs an HTTP GET request and returns the response and body.
func httpGet(ctx context.Context, url string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, "", err
	}

	return resp, string(body), nil
}

// httpPost performs an HTTP POST request.
func httpPost(ctx context.Context, url, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	return client.Do(req)
}

// extractBootEntryNames extracts boot entry names from the menu script.
func extractBootEntryNames(menuScript string) []string {
	var entries []string

	// Match "item <name>" lines, excluding utilities
	re := regexp.MustCompile(`item\s+(\S+)\s+`)
	matches := re.FindAllStringSubmatch(menuScript, -1)

	utilities := map[string]bool{
		"shell":  true,
		"reboot": true,
		"exit":   true,
		"--gap":  true,
	}

	for _, match := range matches {
		if len(match) >= 2 {
			name := match[1]
			if !utilities[name] && !strings.HasPrefix(name, "--") {
				entries = append(entries, name)
			}
		}
	}

	return entries
}

// =============================================================================
// HTTP Client Adapter Implementation
// =============================================================================

// HTTPClientAdapter implements the IPXECommands HTTP operations.
type HTTPClientAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewHTTPClientAdapter creates a new HTTP client adapter.
func NewHTTPClientAdapter(serverIP string, port int) *HTTPClientAdapter {
	return &HTTPClientAdapter{
		baseURL: fmt.Sprintf("http://%s:%d", serverIP, port),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name returns the protocol adapter identifier.
func (h *HTTPClientAdapter) Name() string {
	return "HTTP"
}

// Setup initializes the HTTP client.
func (h *HTTPClientAdapter) Setup(ctx context.Context) error {
	// Verify connectivity by checking health endpoint
	resp, _, err := httpGet(ctx, h.baseURL+"/health")
	if err != nil {
		return fmt.Errorf("HTTP server unreachable: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP server unhealthy: status %d", resp.StatusCode)
	}
	return nil
}

// Teardown cleans up HTTP client resources.
func (h *HTTPClientAdapter) Teardown() error {
	if h.httpClient != nil {
		h.httpClient.CloseIdleConnections()
	}
	return nil
}

// HTTPGetBootScript fetches the boot script.
func (h *HTTPClientAdapter) HTTPGetBootScript(ctx context.Context) (*HTTPBootScriptResult, error) {
	resp, body, err := httpGet(ctx, h.baseURL+"/boot.ipxe")
	if err != nil {
		return nil, err
	}

	return &HTTPBootScriptResult{
		Script:      body,
		ContentType: resp.Header.Get("Content-Type"),
		StatusCode:  resp.StatusCode,
	}, nil
}

// HTTPGetMenuScript fetches the menu script.
func (h *HTTPClientAdapter) HTTPGetMenuScript(ctx context.Context) (*HTTPMenuScriptResult, error) {
	resp, body, err := httpGet(ctx, h.baseURL+"/menu.ipxe")
	if err != nil {
		return nil, err
	}

	entries := extractBootEntryNames(body)

	return &HTTPMenuScriptResult{
		Script:      body,
		ContentType: resp.Header.Get("Content-Type"),
		StatusCode:  resp.StatusCode,
		BootEntries: entries,
	}, nil
}

// HTTPGetBootEntry fetches a boot entry script.
func (h *HTTPClientAdapter) HTTPGetBootEntry(ctx context.Context,
	entryName string) (*HTTPBootEntryResult, error) {

	url := fmt.Sprintf("%s/boot/%s.ipxe", h.baseURL, entryName)
	resp, body, err := httpGet(ctx, url)
	if err != nil {
		return nil, err
	}

	result := &HTTPBootEntryResult{
		EntryName:   entryName,
		Script:      body,
		ContentType: resp.Header.Get("Content-Type"),
		StatusCode:  resp.StatusCode,
	}

	// Extract kernel and initrd URLs from script
	result.KernelURL = extractURLFromScript(body, "kernel")
	result.InitrdURL = extractURLFromScript(body, "initrd")

	return result, nil
}

// HTTPGetHealth fetches the health status.
func (h *HTTPClientAdapter) HTTPGetHealth(ctx context.Context) (*HTTPHealthResult, error) {
	resp, body, err := httpGet(ctx, h.baseURL+"/health")
	if err != nil {
		return nil, err
	}

	var health struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal([]byte(body), &health)

	return &HTTPHealthResult{
		Status:     health.Status,
		StatusCode: resp.StatusCode,
	}, nil
}

// HTTPGetFile fetches a file from the server.
func (h *HTTPClientAdapter) HTTPGetFile(ctx context.Context, path string) (*HTTPFileResult, error) {
	resp, body, err := httpGet(ctx, h.baseURL+path)
	if err != nil {
		return nil, err
	}

	return &HTTPFileResult{
		Path:        path,
		Data:        []byte(body),
		Size:        int64(len(body)),
		ContentType: resp.Header.Get("Content-Type"),
		StatusCode:  resp.StatusCode,
	}, nil
}

// extractURLFromScript extracts a URL from an iPXE script command.
func extractURLFromScript(script, command string) string {
	re := regexp.MustCompile(command + `\s+(\S+)`)
	match := re.FindStringSubmatch(script)
	if len(match) >= 2 {
		return match[1]
	}
	return ""
}
