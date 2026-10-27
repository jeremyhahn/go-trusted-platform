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
	"time"
)

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

// HTTPClientAdapter fetches boot scripts, menus and health from the iPXE HTTP server.
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
		return &AdapterSetupError{Protocol: "HTTP", Err: err}
	}
	if resp.StatusCode != http.StatusOK {
		return &AdapterSetupError{Protocol: "HTTP", Err: ErrServerUnhealthy}
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
	if err := json.Unmarshal([]byte(body), &health); err != nil {
		return nil, err
	}

	return &HTTPHealthResult{
		Status:     health.Status,
		StatusCode: resp.StatusCode,
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
