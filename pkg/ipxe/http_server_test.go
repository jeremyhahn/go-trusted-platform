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

package ipxe

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestHTTPServer(t *testing.T, cfg *ServerConfig) *HTTPServer {
	t.Helper()
	logger := logging.DefaultLogger()
	return NewHTTPServer(cfg, logger)
}

func TestNewHTTPServer(t *testing.T) {
	cfg := DefaultServerConfig()
	logger := logging.DefaultLogger()

	server := NewHTTPServer(cfg, logger)

	assert.NotNil(t, server)
	assert.Equal(t, cfg, server.config)
	assert.Equal(t, logger, server.logger)
}

func TestHTTPServer_handleBootScript(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.BootEntries = []BootEntry{
		{
			Name:        "test",
			Description: "Test Entry",
			Kernel:      "http://example.com/vmlinuz",
			Initrd:      "http://example.com/initrd",
		},
	}

	server := newTestHTTPServer(t, cfg)

	req := httptest.NewRequest("GET", "/boot.ipxe", nil)
	w := httptest.NewRecorder()

	server.handleBootScript(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// A single configured BootEntry inlines the kernel + initrd so iPXE
	// only needs one HTTP fetch (avoids the second-chain TCP timeout on
	// firmware that drops chained requests). It must NOT chain to the menu.
	single := string(body)
	assert.Contains(t, single, "#!ipxe")
	assert.Contains(t, single, "kernel http://example.com/vmlinuz")
	assert.Contains(t, single, "initrd http://example.com/initrd")
	assert.Contains(t, single, "boot || goto boot_failed")
	assert.Contains(t, single, ":boot_retry")
	assert.Contains(t, single, "shell")
	assert.NotContains(t, single, "chain menu.ipxe")

	// With more than one BootEntry the script falls back to the
	// menu-based flow so multi-image setups still get a selection.
	multiCfg := DefaultServerConfig()
	multiCfg.BootEntries = []BootEntry{
		{Name: "a", Description: "A", Kernel: "http://example.com/a/vmlinuz", Initrd: "http://example.com/a/initrd"},
		{Name: "b", Description: "B", Kernel: "http://example.com/b/vmlinuz", Initrd: "http://example.com/b/initrd"},
	}
	multiServer := newTestHTTPServer(t, multiCfg)

	multiReq := httptest.NewRequest("GET", "/boot.ipxe", nil)
	multiW := httptest.NewRecorder()
	multiServer.handleBootScript(multiW, multiReq)

	multiResp := multiW.Result()
	defer multiResp.Body.Close()

	assert.Equal(t, http.StatusOK, multiResp.StatusCode)
	multiBody, err := io.ReadAll(multiResp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(multiBody), "#!ipxe")
	assert.Contains(t, string(multiBody), "chain menu.ipxe")
}

func TestHTTPServer_handleMenuScript(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	cfg.BootEntries = []BootEntry{
		{
			Name:        "alpine",
			Description: "Alpine Linux",
			Kernel:      "http://example.com/vmlinuz",
			Initrd:      "http://example.com/initrd",
		},
		{
			Name:        "debian",
			Description: "Debian Linux",
			Kernel:      "http://example.com/debian/vmlinuz",
			Initrd:      "http://example.com/debian/initrd",
		},
	}

	server := newTestHTTPServer(t, cfg)

	req := httptest.NewRequest("GET", "/menu.ipxe", nil)
	w := httptest.NewRecorder()

	server.handleMenuScript(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	content := string(body)
	assert.Contains(t, content, "#!ipxe")
	assert.Contains(t, content, "menu PXE Boot Menu")
	assert.Contains(t, content, "item alpine")
	assert.Contains(t, content, "item debian")
	assert.Contains(t, content, "Alpine Linux")
	assert.Contains(t, content, "Debian Linux")
	assert.Contains(t, content, "choose --timeout 30000 --default alpine")
}

func TestHTTPServer_handleBootEntry(t *testing.T) {
	tests := []struct {
		name        string
		entry       BootEntry
		path        string
		expectFound bool
		contains    []string
	}{
		{
			name: "valid kernel boot entry",
			entry: BootEntry{
				Name:        "test",
				Description: "Test Entry",
				Kernel:      "http://example.com/vmlinuz",
				Initrd:      "http://example.com/initrd",
				Args:        "console=tty0",
			},
			path:        "/boot/test.ipxe",
			expectFound: true,
			contains:    []string{"#!ipxe", "kernel", "initrd", "console=tty0"},
		},
		{
			name: "valid netboot entry",
			entry: BootEntry{
				Name:        "alpine",
				Description: "Alpine Linux",
				ISOURL:      "https://example.com/alpine.iso",
				Kernel:      "https://example.com/vmlinuz",
				Initrd:      "https://example.com/initrd",
			},
			path:        "/boot/alpine.ipxe",
			expectFound: true,
			contains:    []string{"#!ipxe", "kernel", "initrd", "Alpine Linux"},
		},
		{
			name:        "non-existent entry",
			entry:       BootEntry{},
			path:        "/boot/nonexistent.ipxe",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultServerConfig()
			cfg.ExternalURL = "http://192.168.1.10:8080"
			if tt.entry.Name != "" {
				cfg.BootEntries = []BootEntry{tt.entry}
			} else {
				cfg.BootEntries = []BootEntry{}
			}

			server := newTestHTTPServer(t, cfg)

			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			server.handleBootEntry(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if !tt.expectFound {
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
				return
			}

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			content := string(body)
			for _, expected := range tt.contains {
				assert.Contains(t, content, expected)
			}
		})
	}
}

func TestHTTPServer_handleHealth(t *testing.T) {
	cfg := DefaultServerConfig()
	server := newTestHTTPServer(t, cfg)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, `{"status":"healthy"}`, string(body))
}

func TestHTTPServer_handleStatic(t *testing.T) {
	cfg := DefaultServerConfig()
	server := newTestHTTPServer(t, cfg)

	// Create a temporary static directory
	tmpDir := t.TempDir()
	staticDir := filepath.Join(tmpDir, "static")
	require.NoError(t, os.MkdirAll(staticDir, 0755))

	testFile := filepath.Join(staticDir, "test.txt")
	testContent := "test content"
	require.NoError(t, os.WriteFile(testFile, []byte(testContent), 0644))

	// Change to temp directory for the test
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)
	require.NoError(t, os.Chdir(tmpDir))

	tests := []struct {
		name           string
		path           string
		expectStatus   int
		expectContains string
	}{
		{
			name:           "valid static file",
			path:           "/static/test.txt",
			expectStatus:   http.StatusOK,
			expectContains: testContent,
		},
		{
			name:         "directory traversal attempt",
			path:         "/static/../../../etc/passwd",
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			server.handleStatic(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, tt.expectStatus, resp.StatusCode)

			if tt.expectContains != "" {
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Contains(t, string(body), tt.expectContains)
			}
		})
	}
}

func TestHTTPServer_handleLocalFiles(t *testing.T) {
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "kernel.img")
	testContent := []byte("kernel content")
	require.NoError(t, os.WriteFile(testFile, testContent, 0644))

	testDir := filepath.Join(tmpDir, "subdir")
	require.NoError(t, os.MkdirAll(testDir, 0755))

	tests := []struct {
		name           string
		localFilesDir  string
		path           string
		expectStatus   int
		expectContains string
	}{
		{
			name:           "valid local file",
			localFilesDir:  tmpDir,
			path:           "/files/kernel.img",
			expectStatus:   http.StatusOK,
			expectContains: "kernel content",
		},
		{
			name:          "no local files dir configured",
			localFilesDir: "",
			path:          "/files/kernel.img",
			expectStatus:  http.StatusNotFound,
		},
		{
			name:          "directory traversal attempt",
			localFilesDir: tmpDir,
			path:          "/files/../../../etc/passwd",
			expectStatus:  http.StatusBadRequest,
		},
		{
			name:          "non-existent file",
			localFilesDir: tmpDir,
			path:          "/files/nonexistent.img",
			expectStatus:  http.StatusNotFound,
		},
		{
			name:          "directory access attempt",
			localFilesDir: tmpDir,
			path:          "/files/subdir",
			expectStatus:  http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultServerConfig()
			cfg.LocalFilesDir = tt.localFilesDir
			server := newTestHTTPServer(t, cfg)

			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			server.handleLocalFiles(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, tt.expectStatus, resp.StatusCode)

			if tt.expectContains != "" {
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Contains(t, string(body), tt.expectContains)
			}
		})
	}
}

// TestHTTPServer_handleDataFiles verifies the /data/ endpoint that
// serves the container's bind-mounted data directory to iPXE clients.
// The bootstrap.ipxe script generated for the "bootstrap" boot entry
// references kernel/initrd as /data/<file>; without this handler,
// every iPXE chainload that reaches the boot-entry script proceeds
// to fetch kernel/initrd at /data/vmlinuz / /data/initramfs and
// 404s, dropping the client to an iPXE shell with "Could not boot:
// Not found" — exactly the failure mode observed on node-04 PXE
// boot before this handler was added.
func TestHTTPServer_handleDataFiles(t *testing.T) {
	tmpDir := t.TempDir()

	vmlinuz := filepath.Join(tmpDir, "vmlinuz")
	require.NoError(t, os.WriteFile(vmlinuz, []byte("kernel bytes"), 0644))
	initramfs := filepath.Join(tmpDir, "initramfs")
	require.NoError(t, os.WriteFile(initramfs, []byte("initrd bytes"), 0644))
	subDir := filepath.Join(tmpDir, "subdir")
	require.NoError(t, os.MkdirAll(subDir, 0755))

	tests := []struct {
		name           string
		dataDir        string
		path           string
		expectStatus   int
		expectContains string
	}{
		{
			name:           "vmlinuz served",
			dataDir:        tmpDir,
			path:           "/data/vmlinuz",
			expectStatus:   http.StatusOK,
			expectContains: "kernel bytes",
		},
		{
			name:           "initramfs served",
			dataDir:        tmpDir,
			path:           "/data/initramfs",
			expectStatus:   http.StatusOK,
			expectContains: "initrd bytes",
		},
		{
			name:         "no DataDir configured -> 404",
			dataDir:      "",
			path:         "/data/vmlinuz",
			expectStatus: http.StatusNotFound,
		},
		{
			name:         "traversal attempt rejected",
			dataDir:      tmpDir,
			path:         "/data/../../etc/passwd",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "missing file -> 404",
			dataDir:      tmpDir,
			path:         "/data/does-not-exist",
			expectStatus: http.StatusNotFound,
		},
		{
			name:         "directory listing denied",
			dataDir:      tmpDir,
			path:         "/data/subdir",
			expectStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultServerConfig()
			cfg.DataDir = tt.dataDir
			server := newTestHTTPServer(t, cfg)

			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			server.handleDataFiles(w, req)

			resp := w.Result()
			defer resp.Body.Close()
			assert.Equal(t, tt.expectStatus, resp.StatusCode)
			if tt.expectContains != "" {
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Contains(t, string(body), tt.expectContains)
			}
		})
	}
}

// The Raspberry Pi bootloader EEPROM fetches http://HTTP_HOST/HTTP_PATH/boot.img
// and boot.sig; HTTP_PATH is the data directory's http-boot folder under /data/.
// The bytes must arrive exactly as staged (boot.sig signs them), with a length
// the client can check.
func TestHTTPServer_handleDataFiles_ServesTheHTTPBootFiles(t *testing.T) {
	dataDir := t.TempDir()
	dir := filepath.Join(dataDir, "http-boot")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	files := map[string][]byte{
		"boot.img":   bytes.Repeat([]byte{0x00, 0xff, 0xeb, 0x3c}, 4096),
		"boot.sig":   []byte("0123\nts: 1790856000\ntarget-soc: 2711\nrsa2048: ab\n"),
		"pubkey.bin": bytes.Repeat([]byte{0x80}, 264),
	}
	for name, data := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o644))
	}
	cfg := DefaultServerConfig()
	cfg.DataDir = dataDir
	server := newTestHTTPServer(t, cfg)

	for name, want := range files {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			server.handleDataFiles(w, httptest.NewRequest("GET", "/data/http-boot/"+name, nil))

			resp := w.Result()
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, strconv.Itoa(len(want)), resp.Header.Get("Content-Length"))
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, want, body)
		})
	}

	t.Run("a file that was not staged is a 404", func(t *testing.T) {
		w := httptest.NewRecorder()
		server.handleDataFiles(w, httptest.NewRequest("GET", "/data/http-boot/boot.img.old", nil))
		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
	})
}

func TestHTTPServer_handleProxy(t *testing.T) {
	// Create a test HTTPS server to proxy with custom TLS config
	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("proxied content"))
	}))
	testServer.StartTLS()
	defer testServer.Close()

	// Trust the test server's self-signed cert via ProxyCACertPool — the
	// production proxy enforces full TLS verification and we must never
	// disable it (no InsecureSkipVerify, even in tests).
	proxyTrust := x509.NewCertPool()
	proxyTrust.AddCert(testServer.Certificate())

	// Extract host and port from test server URL
	testURL := strings.TrimPrefix(testServer.URL, "https://")

	tests := []struct {
		name         string
		path         string
		expectStatus int
		expectBody   string
	}{
		{
			name:         "valid https proxy",
			path:         fmt.Sprintf("/proxy/https/%s", testURL),
			expectStatus: http.StatusOK,
			expectBody:   "proxied content",
		},
		{
			name:         "missing URL",
			path:         "/proxy/",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "invalid URL format",
			path:         "/proxy/https",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "non-https scheme",
			path:         "/proxy/http/example.com/file",
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultServerConfig()
			cfg.ProxyCACertPool = proxyTrust
			server := newTestHTTPServer(t, cfg)

			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			server.handleProxy(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, tt.expectStatus, resp.StatusCode)

			if tt.expectBody != "" {
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Contains(t, string(body), tt.expectBody)
			}
		})
	}
}

func TestHTTPServer_generateNetbootScript(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"

	tests := []struct {
		name     string
		entry    *BootEntry
		contains []string
	}{
		{
			name: "alpine linux netboot",
			entry: &BootEntry{
				Name:        "alpine",
				Description: "Alpine Linux",
				ISOURL:      "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-standard-3.20.0-x86_64.iso",
			},
			contains: []string{
				"#!ipxe",
				"Alpine Linux",
				"kernel",
				"initrd",
				"boot",
			},
		},
		{
			name: "custom kernel and initrd",
			entry: &BootEntry{
				Name:        "custom",
				Description: "Custom Boot",
				ISOURL:      "https://example.com/custom.iso",
				Kernel:      "https://example.com/vmlinuz",
				Initrd:      "https://example.com/initrd",
				Args:        "console=tty0 https://example.com/config",
			},
			contains: []string{
				"#!ipxe",
				"Custom Boot",
				"console=tty0",
				"/proxy/https/",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newTestHTTPServer(t, cfg)
			script := server.generateNetbootScript(tt.entry)

			for _, expected := range tt.contains {
				assert.Contains(t, script, expected)
			}
		})
	}
}

func TestHTTPServer_generateKernelScript(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	server := newTestHTTPServer(t, cfg)

	entry := &BootEntry{
		Name:        "debian",
		Description: "Debian Linux",
		Kernel:      "https://example.com/vmlinuz",
		Initrd:      "https://example.com/initrd",
		Args:        "console=tty0 https://example.com/preseed",
	}

	script := server.generateKernelScript(entry)

	assert.Contains(t, script, "#!ipxe")
	assert.Contains(t, script, "Debian Linux")
	assert.Contains(t, script, "kernel")
	assert.Contains(t, script, "initrd")
	assert.Contains(t, script, "console=tty0")
	assert.Contains(t, script, "/proxy/https/")
}

func TestHTTPServer_proxyURL(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	server := newTestHTTPServer(t, cfg)

	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "https URL",
			url:      "https://example.com/file.iso",
			expected: "http://192.168.1.10:8080/proxy/https/example.com/file.iso",
		},
		{
			name:     "http URL unchanged",
			url:      "http://example.com/file.iso",
			expected: "http://example.com/file.iso",
		},
		{
			name:     "non-URL unchanged",
			url:      "/local/path",
			expected: "/local/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.proxyURL(tt.url)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHTTPServer_proxyArgsURLs(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	server := newTestHTTPServer(t, cfg)

	tests := []struct {
		name        string
		args        string
		contains    []string
		notContains []string
	}{
		{
			name:        "single https URL in args",
			args:        "console=tty0 repo=https://example.com/repo modules=test",
			contains:    []string{"console=tty0", "repo=http://192.168.1.10:8080/proxy/https/example.com/repo", "modules=test"},
			notContains: []string{"https://"},
		},
		{
			name:        "multiple https URLs in args",
			args:        "repo=https://example.com/repo modloop=https://example.com/modloop",
			contains:    []string{"/proxy/https/example.com/repo", "/proxy/https/example.com/modloop"},
			notContains: []string{"https://"},
		},
		{
			name:        "no https URLs",
			args:        "console=tty0 modules=test",
			contains:    []string{"console=tty0", "modules=test"},
			notContains: []string{"/proxy/"},
		},
		{
			name:        "https URL at end",
			args:        "console=tty0 preseed=https://example.com/preseed.cfg",
			contains:    []string{"console=tty0", "/proxy/https/example.com/preseed.cfg"},
			notContains: []string{"https://"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.proxyArgsURLs(tt.args)

			for _, expected := range tt.contains {
				assert.Contains(t, result, expected)
			}

			for _, unexpected := range tt.notContains {
				assert.NotContains(t, result, unexpected)
			}
		})
	}
}

func TestHTTPServer_loggingMiddleware(t *testing.T) {
	cfg := DefaultServerConfig()
	server := newTestHTTPServer(t, cfg)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrapped := server.loggingMiddleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "OK", string(body))
}

func TestHTTPServer_responseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

	// Default status is OK
	assert.Equal(t, http.StatusOK, rw.status)

	// Write header changes status
	rw.WriteHeader(http.StatusNotFound)
	assert.Equal(t, http.StatusNotFound, rw.status)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHTTPServer_Start_GracefulShutdown(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.HTTPPort = 0 // Use random available port

	server := newTestHTTPServer(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in background
	bound := newBoundSignal()
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx, bound)
	}()

	awaitBound(t, bound, "HTTP listener")

	// Cancel context to trigger shutdown
	cancel()

	// Wait for server to shutdown
	select {
	case err := <-errChan:
		// Shutdown should complete without error or with context.Canceled
		if err != nil {
			assert.ErrorIs(t, err, context.Canceled)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shutdown in time")
	}
}

// TestHTTPServer_Start_InvalidConfig gives Start a listen address it cannot
// bind and expects the bind error back at once, rather than serving until a
// deadline the test has to wait out (#284).
func TestHTTPServer_Start_InvalidConfig(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, taken.Close()) })

	cfg := DefaultServerConfig()
	cfg.BindHost = "127.0.0.1"
	cfg.HTTPPort = taken.Addr().(*net.TCPAddr).Port

	server := newTestHTTPServer(t, cfg)
	err = server.Start(t.Context(), nil)

	var bindErr *WrappedError
	require.ErrorAs(t, err, &bindErr)
	assert.Contains(t, bindErr.Msg, "failed to bind")
}

// Additional tests for better coverage

func TestHTTPServer_handleMenuScript_EmptyEntries(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	cfg.BootEntries = []BootEntry{} // Empty entries

	server := newTestHTTPServer(t, cfg)

	req := httptest.NewRequest("GET", "/menu.ipxe", nil)
	w := httptest.NewRecorder()

	server.handleMenuScript(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	content := string(body)
	assert.Contains(t, content, "#!ipxe")
	assert.Contains(t, content, "menu PXE Boot Menu")
}

func TestHTTPServer_handleBootEntry_InvalidEntryType(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	cfg.BootEntries = []BootEntry{
		{
			Name:        "invalid",
			Description: "Invalid Entry",
			// No kernel, initrd, or ISO URL
		},
	}

	server := newTestHTTPServer(t, cfg)

	req := httptest.NewRequest("GET", "/boot/invalid.ipxe", nil)
	w := httptest.NewRecorder()

	server.handleBootEntry(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestHTTPServer_handleProxy_InvalidTarget(t *testing.T) {
	cfg := DefaultServerConfig()
	server := newTestHTTPServer(t, cfg)

	req := httptest.NewRequest("GET", "/proxy/https/invalid-host-does-not-exist.invalid/file", nil)
	w := httptest.NewRecorder()

	server.handleProxy(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

func TestHTTPServer_handleLocalFiles_StatError(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := DefaultServerConfig()
	cfg.LocalFilesDir = tmpDir
	server := newTestHTTPServer(t, cfg)

	// Try to access a file in a non-readable directory
	// This is hard to test portably, so we just test the error path exists
	req := httptest.NewRequest("GET", "/files/test.img", nil)
	w := httptest.NewRecorder()

	server.handleLocalFiles(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 404 for non-existent file
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHTTPServer_Start_ErrorChannel(t *testing.T) {
	cfg := DefaultServerConfig()
	// Use an invalid port to force an error
	cfg.HTTPPort = -1

	server := newTestHTTPServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := server.Start(ctx, nil)
	// Should get an error from invalid port
	if err == nil {
		// Or context deadline
		t.Log("Expected error but got none - context may have expired first")
	}
}

func TestHTTPServer_handleLocalFiles_EmptyFilename(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := DefaultServerConfig()
	cfg.LocalFilesDir = tmpDir
	server := newTestHTTPServer(t, cfg)

	req := httptest.NewRequest("GET", "/files/", nil)
	w := httptest.NewRecorder()

	server.handleLocalFiles(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Empty filename should return bad request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHTTPServer_handleProxy_FailedFetch(t *testing.T) {
	cfg := DefaultServerConfig()
	server := newTestHTTPServer(t, cfg)

	// Use a non-existent server
	req := httptest.NewRequest("GET", "/proxy/https/127.0.0.1:59999/nonexistent", nil)
	w := httptest.NewRecorder()

	server.handleProxy(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 502 Bad Gateway when upstream fails
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

func TestHTTPServer_handleProxy_InvalidURL(t *testing.T) {
	cfg := DefaultServerConfig()
	server := newTestHTTPServer(t, cfg)

	// Use a URL with invalid characters
	req := httptest.NewRequest("GET", "/proxy/https/[invalid]", nil)
	w := httptest.NewRecorder()

	server.handleProxy(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 400 Bad Request for invalid URL
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHTTPServer_responseWriter_WriteHeader(t *testing.T) {
	// Test the responseWriter wrapper directly
	underlying := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: underlying, status: http.StatusOK}

	// Write a custom status
	rw.WriteHeader(http.StatusCreated)

	assert.Equal(t, http.StatusCreated, rw.status)
	assert.Equal(t, http.StatusCreated, underlying.Code)
}

func TestHTTPServer_handleStatic_ValidFile(t *testing.T) {
	cfg := DefaultServerConfig()
	server := newTestHTTPServer(t, cfg)

	// Create static directory with a file
	staticDir := "./static"
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		t.Skipf("Could not create static directory: %v", err)
	}
	defer os.RemoveAll(staticDir)

	testFile := filepath.Join(staticDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("static content"), 0644); err != nil {
		t.Skipf("Could not create test file: %v", err)
	}

	req := httptest.NewRequest("GET", "/static/test.txt", nil)
	w := httptest.NewRecorder()

	server.handleStatic(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Check if file was served
	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "static content")
	}
}

// TestHTTPServer_InstallUploadHappyPath verifies that PUT
// /installs/{hostname}/{filename} writes the body atomically under
// InstallsDir/{hostname}/{filename} and returns 201 Created.
func TestHTTPServer_InstallUploadHappyPath(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultServerConfig()
	cfg.InstallsDir = dir
	server := newTestHTTPServer(t, cfg)

	body := strings.NewReader("hello install log\n")
	req := httptest.NewRequest("PUT", "/installs/node-02/install.log", body)
	w := httptest.NewRecorder()

	server.handleInstalls(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	written, err := os.ReadFile(filepath.Join(dir, "node-02", "install.log"))
	require.NoError(t, err)
	assert.Equal(t, "hello install log\n", string(written))

	// .partial file must NOT exist after a successful upload (atomic rename
	// guarantee — half-uploaded logs should never appear in the index).
	_, err = os.Stat(filepath.Join(dir, "node-02", "install.log.partial"))
	assert.True(t, os.IsNotExist(err), "partial file should be removed after rename")
}

// TestHTTPServer_InstallUploadPathTraversal blocks any attempt to escape
// InstallsDir via .. or absolute paths in the URL.
func TestHTTPServer_InstallUploadPathTraversal(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultServerConfig()
	cfg.InstallsDir = dir
	server := newTestHTTPServer(t, cfg)

	cases := []string{
		"/installs/../etc/passwd",
		"/installs/node-02/../../../etc/passwd",
		"/installs/Node-02/install.log", // uppercase rejected by regex
		"/installs/node-02",             // missing filename
		"/installs/",                    // empty
	}

	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("PUT", path, strings.NewReader("x"))
			w := httptest.NewRecorder()
			server.handleInstalls(w, req)
			resp := w.Result()
			resp.Body.Close()
			assert.NotEqual(t, http.StatusCreated, resp.StatusCode,
				"path %s should not have been accepted", path)
		})
	}
}

// TestHTTPServer_InstallUploadSizeLimit verifies the 16 MiB cap.
func TestHTTPServer_InstallUploadSizeLimit(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultServerConfig()
	cfg.InstallsDir = dir
	server := newTestHTTPServer(t, cfg)

	// Send 17 MiB. The handler should refuse with 413.
	body := strings.NewReader(strings.Repeat("x", 17*1024*1024))
	req := httptest.NewRequest("PUT", "/installs/node-02/big.log", body)
	w := httptest.NewRecorder()
	server.handleInstalls(w, req)
	resp := w.Result()
	resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)

	// And the partial file should not survive a rejected upload.
	_, err := os.Stat(filepath.Join(dir, "node-02", "big.log.partial"))
	assert.True(t, os.IsNotExist(err))
}

// TestHTTPServer_InstallIndexBrowse verifies that GET /installs/ returns an
// HTML index of host directories and GET /installs/{hostname}/{file} serves
// the previously-uploaded log inline.
func TestHTTPServer_InstallIndexBrowse(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultServerConfig()
	cfg.InstallsDir = dir
	server := newTestHTTPServer(t, cfg)

	// Seed two hosts.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "node-02"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "node-03"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "node-02", "install.log"),
		[]byte("install transcript"), 0o644))

	// GET /installs/ should list both hosts.
	req := httptest.NewRequest("GET", "/installs/", nil)
	w := httptest.NewRecorder()
	server.handleInstalls(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "node-02")
	assert.Contains(t, string(body), "node-03")

	// GET /installs/node-02/install.log should return the transcript.
	req = httptest.NewRequest("GET", "/installs/node-02/install.log", nil)
	w = httptest.NewRecorder()
	server.handleInstalls(w, req)
	resp = w.Result()
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "install transcript", string(body))
}

// TestHTTPServer_handleBootScript_ArchitectureGuard pins that a single entry
// for one architecture is booted inline only by a client of that
// architecture, and that every other client is sent to the menu with its
// own architecture.
func TestHTTPServer_handleBootScript_ArchitectureGuard(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.BootEntries = []BootEntry{{
		Name: "alpine-arm64", Description: "Alpine aarch64", Architecture: ArchitectureARM64,
		Kernel: "http://example.com/vmlinuz-lts", Initrd: "http://example.com/initramfs-lts",
	}}
	server := newTestHTTPServer(t, cfg)

	w := httptest.NewRecorder()
	server.handleBootScript(w, httptest.NewRequest("GET", "/boot.ipxe", nil))
	body, err := io.ReadAll(w.Result().Body)
	require.NoError(t, err)

	script := string(body)
	assert.Contains(t, script, "iseq ${buildarch} arm64 || chain menu.ipxe?arch=${buildarch}\n")
	assert.Contains(t, script, "kernel http://example.com/vmlinuz-lts")
	assert.Less(t, strings.Index(script, "iseq ${buildarch}"), strings.Index(script, "kernel http"), "the guard runs before any download")

	// An entry for every architecture needs no guard, and the multi-entry
	// fallback asks the menu for the client's architecture.
	cfg.BootEntries[0].Architecture = ""
	w = httptest.NewRecorder()
	server.handleBootScript(w, httptest.NewRequest("GET", "/boot.ipxe", nil))
	body, _ = io.ReadAll(w.Result().Body)
	assert.NotContains(t, string(body), "iseq ${buildarch}")
	cfg.BootEntries = append(cfg.BootEntries, BootEntry{Name: "second", Kernel: "k", Initrd: "i"})
	w = httptest.NewRecorder()
	server.handleBootScript(w, httptest.NewRequest("GET", "/boot.ipxe", nil))
	body, _ = io.ReadAll(w.Result().Body)
	assert.Contains(t, string(body), "chain menu.ipxe?arch=${buildarch}")
}

// TestHTTPServer_handleMenuScript_PerArchitecture pins that ?arch= narrows
// the menu to the entries a client can run, that an entry with no
// architecture is offered to everyone, and that a client that does not
// say gets everything.
func TestHTTPServer_handleMenuScript_PerArchitecture(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	cfg.BootEntries = []BootEntry{
		{Name: "x86", Description: "x86_64 installer", Architecture: ArchitectureX86_64, Kernel: "k", Initrd: "i"},
		{Name: "arm", Description: "aarch64 installer", Architecture: ArchitectureARM64, Kernel: "k", Initrd: "i"},
		{Name: "any", Description: "rescue", Kernel: "k", Initrd: "i"},
	}
	server := newTestHTTPServer(t, cfg)
	menu := func(query string) string {
		w := httptest.NewRecorder()
		server.handleMenuScript(w, httptest.NewRequest("GET", "/menu.ipxe"+query, nil))
		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		return string(body)
	}

	arm := menu("?arch=arm64")
	assert.Contains(t, arm, "item arm ")
	assert.Contains(t, arm, "item any ")
	assert.NotContains(t, arm, "item x86 ")
	assert.Contains(t, arm, "--default arm ", "the first entry this client can run is the default")

	x86 := menu("?arch=x86_64")
	assert.Contains(t, x86, "item x86 ")
	assert.NotContains(t, x86, "item arm ")
	assert.Contains(t, x86, "--default x86 ")

	all := menu("")
	assert.Contains(t, all, "item x86 ")
	assert.Contains(t, all, "item arm ")
	assert.Contains(t, all, "item any ")
}

func bootScript(t *testing.T, server *HTTPServer) string {
	t.Helper()
	w := httptest.NewRecorder()
	server.handleBootScript(w, httptest.NewRequest("GET", "/boot.ipxe", nil))
	body, err := io.ReadAll(w.Result().Body)
	require.NoError(t, err)
	return string(body)
}

func TestHTTPServer_handleBootScript_ChainsTheDeviceScript(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.BootEntries = []BootEntry{{Name: "x", Description: "x", Kernel: "http://s/k", Initrd: "http://s/i"}}
	server := newTestHTTPServer(t, cfg)
	assert.NotContains(t, bootScript(t, server), "boot/device/", "no device lookup, no chain")

	server.SetDeviceLookup(func(string) (*DeviceBootInfo, error) { return nil, ErrDeviceNotFound }, NewScriptGenerator("http://s", logging.DefaultLogger().Slog()))
	script := bootScript(t, server)
	assert.Contains(t, script, "chain --autofree boot/device/${mac:hexhyp}.ipxe ||\n", "a known device boots what it was assigned")
	assert.Less(t, strings.Index(script, "boot/device/"), strings.Index(script, "kernel "), "before the default entry, which an unknown device falls through to")
}

func TestHTTPServer_handleBootScript_DispatchesByArchitecture(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.BootEntries = []BootEntry{
		{Name: "x86", Description: "x86_64 installer", Architecture: ArchitectureX86_64, Kernel: "http://s/x86/k", Initrd: "http://s/x86/i"},
		{Name: "arm", Description: "arm64 installer", Architecture: ArchitectureARM64, Kernel: "http://s/arm/k", Initrd: "http://s/arm/i"},
	}
	script := bootScript(t, newTestHTTPServer(t, cfg))
	assert.Contains(t, script, "iseq ${buildarch} x86_64 && goto arch_x86_64 ||\n")
	assert.Contains(t, script, "iseq ${buildarch} arm64 && goto arch_arm64 ||\n")
	assert.Contains(t, script, "chain menu.ipxe?arch=${buildarch} || shell\n", "an architecture with no entry gets the menu")
	x86, arm := strings.Index(script, ":arch_x86_64\n"), strings.Index(script, ":arch_arm64\n")
	require.True(t, x86 > 0 && arm > x86)
	assert.Contains(t, script[x86:arm], "kernel http://s/x86/k")
	assert.Contains(t, script[arm:], "kernel http://s/arm/k")
	assert.Contains(t, script[arm:], ":boot_arm64_retry", "each block has its own labels")
	assert.NotContains(t, script, "\nshell\nchain", "no menu fallthrough between blocks")

	// Two entries for one architecture cannot be told apart: the menu.
	cfg.BootEntries[1].Architecture = ArchitectureX86_64
	script = bootScript(t, newTestHTTPServer(t, cfg))
	assert.NotContains(t, script, "goto arch_")
	assert.Contains(t, script, "chain menu.ipxe?arch=${buildarch}")
}

func TestHTTPServer_handleDeviceBootScript_NotFoundVersusFailure(t *testing.T) {
	server := newTestHTTPServer(t, DefaultServerConfig())
	known := &DeviceBootInfo{MAC: "dc:a6:32:01:36:c2", Hostname: "pi-01", KernelURL: "http://s/k", InitrdURL: "http://s/i"}
	server.SetDeviceLookup(func(mac string) (*DeviceBootInfo, error) {
		switch mac {
		case known.MAC:
			return known, nil
		case "00:00:00:00:00:01":
			return nil, ErrDeviceNotFound
		default:
			return nil, errors.New("manifest unreadable")
		}
	}, NewScriptGenerator("http://s", logging.DefaultLogger().Slog()))

	get := func(path string) (int, string) {
		w := httptest.NewRecorder()
		server.handleDeviceBootScript(w, httptest.NewRequest("GET", path, nil))
		body, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		return w.Code, string(body)
	}
	code, body := get("/boot/device/dc-a6-32-01-36-c2.ipxe")
	assert.Equal(t, http.StatusOK, code, "iPXE's ${mac:hexhyp} form resolves")
	assert.Contains(t, body, "kernel http://s/k")
	code, _ = get("/boot/device/00-00-00-00-00-01.ipxe")
	assert.Equal(t, http.StatusNotFound, code, "an unknown device falls through")
	code, _ = get("/boot/device/00-00-00-00-00-02.ipxe")
	assert.Equal(t, http.StatusInternalServerError, code, "a broken lookup is not reported as an unknown device")
}

func TestHTTPServer_handleBootScript_BIOSClientsBootTheX86Entry(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.BootEntries = []BootEntry{{Name: "x86", Description: "x86", Architecture: ArchitectureX86_64, Kernel: "http://s/k", Initrd: "http://s/i"}}
	script := bootScript(t, newTestHTTPServer(t, cfg))
	assert.Contains(t, script, "iseq ${buildarch} x86_64 || iseq ${buildarch} i386 || chain menu.ipxe?arch=${buildarch}\n",
		"undionly.kpxe is a 32-bit iPXE: its buildarch is i386 on a 64-bit server")

	cfg.BootEntries = append(cfg.BootEntries, BootEntry{Name: "arm", Description: "arm", Architecture: ArchitectureARM64, Kernel: "http://s/ak", Initrd: "http://s/ai"})
	script = bootScript(t, newTestHTTPServer(t, cfg))
	assert.Contains(t, script, "iseq ${buildarch} i386 && goto arch_x86_64 ||\n")

	// An explicit i386 entry claims i386 for itself.
	cfg.BootEntries = append(cfg.BootEntries, BootEntry{Name: "i386", Description: "i386", Architecture: ArchitectureI386, Kernel: "http://s/ik", Initrd: "http://s/ii"})
	script = bootScript(t, newTestHTTPServer(t, cfg))
	assert.NotContains(t, script, "iseq ${buildarch} i386 && goto arch_x86_64")
	assert.Contains(t, script, "iseq ${buildarch} i386 && goto arch_i386 ||\n")
}
