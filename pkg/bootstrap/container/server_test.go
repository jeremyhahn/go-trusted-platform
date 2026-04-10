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

package container

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func writeTestManifest(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "manifest.yaml")
	content := `nodes:
  - mac: "aa:bb:cc:dd:ee:01"
    role: "control-plane"
    hostname: "cp-01"
  - mac: "aa:bb:cc:dd:ee:02"
    role: "worker"
    hostname: "worker-01"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHandleDeviceBootScript_Found(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeTestManifest(t, dir)

	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{
		manifest: manifest,
		config: &ServerConfig{
			HTTPPort: 8080,
			DHCPConfig: DHCPConfig{
				ServerIP: "192.168.1.1",
			},
		},
		logger: testLogger(),
	}

	req := httptest.NewRequest(http.MethodGet, "/boot/device/aa:bb:cc:dd:ee:01.ipxe", nil)
	w := httptest.NewRecorder()

	server.HandleDeviceBootScript(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body := w.Body.String()

	if !strings.Contains(body, "#!ipxe") {
		t.Error("expected iPXE shebang in response")
	}
	if !strings.Contains(body, "platform_role=control-plane") {
		t.Error("expected platform_role=control-plane in response")
	}
	if !strings.Contains(body, "platform_hostname=cp-01") {
		t.Error("expected platform_hostname=cp-01 in response")
	}
	if !strings.Contains(body, "192.168.1.1:8080") {
		t.Error("expected server IP and port in kernel URL")
	}
}

func TestHandleDeviceBootScript_NotFound(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeTestManifest(t, dir)

	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{
		manifest: manifest,
		config: &ServerConfig{
			HTTPPort: 8080,
			DHCPConfig: DHCPConfig{
				ServerIP: "192.168.1.1",
			},
		},
		logger: testLogger(),
	}

	req := httptest.NewRequest(http.MethodGet, "/boot/device/ff:ff:ff:ff:ff:ff.ipxe", nil)
	w := httptest.NewRecorder()

	server.HandleDeviceBootScript(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for default menu, got %d", resp.StatusCode)
	}

	body := w.Body.String()

	if !strings.Contains(body, "#!ipxe") {
		t.Error("expected iPXE shebang in response")
	}
	if !strings.Contains(body, "Unknown device") {
		t.Error("expected 'Unknown device' in default menu response")
	}
	// Must NOT contain role-specific args
	if strings.Contains(body, "platform_role=") {
		t.Error("default menu should not contain platform_role")
	}
}

func TestHandleDeviceBootScript_MissingMAC(t *testing.T) {
	server := &Server{
		manifest: &Manifest{},
		config: &ServerConfig{
			HTTPPort:   8080,
			DHCPConfig: DHCPConfig{ServerIP: "192.168.1.1"},
		},
		logger: testLogger(),
	}

	req := httptest.NewRequest(http.MethodGet, "/boot/device/", nil)
	w := httptest.NewRecorder()

	server.HandleDeviceBootScript(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing MAC, got %d", w.Result().StatusCode)
	}
}

func TestHandleDeviceBootScript_DashSeparatedMAC(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writeTestManifest(t, dir)

	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{
		manifest: manifest,
		config: &ServerConfig{
			HTTPPort: 8080,
			DHCPConfig: DHCPConfig{
				ServerIP: "192.168.1.1",
			},
		},
		logger: testLogger(),
	}

	// Use dash-separated MAC
	req := httptest.NewRequest(http.MethodGet, "/boot/device/aa-bb-cc-dd-ee-01.ipxe", nil)
	w := httptest.NewRecorder()

	server.HandleDeviceBootScript(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "platform_role=control-plane") {
		t.Error("expected dash-separated MAC to resolve to control-plane device")
	}
}

func TestNewServer_NilConfig(t *testing.T) {
	_, err := NewServer(nil, testLogger())
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	var target ErrInvalidServerConfig
	if !errors.As(err, &target) {
		t.Errorf("expected ErrInvalidServerConfig, got %T: %v", err, err)
	}
}

func TestNewServer_NilLogger(t *testing.T) {
	_, err := NewServer(&ServerConfig{}, nil)
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
	var target ErrInvalidServerConfig
	if !errors.As(err, &target) {
		t.Errorf("expected ErrInvalidServerConfig, got %T: %v", err, err)
	}
}

func TestNewServer_InvalidConfig(t *testing.T) {
	_, err := NewServer(&ServerConfig{
		ManifestPath: "",
		KernelPath:   "",
		InitrdPath:   "",
	}, testLogger())
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
	var target ErrInvalidServerConfig
	if !errors.As(err, &target) {
		t.Errorf("expected ErrInvalidServerConfig, got %T: %v", err, err)
	}
}

func TestNewServer_ManifestNotFound(t *testing.T) {
	_, err := NewServer(&ServerConfig{
		ManifestPath: "/nonexistent/manifest.yaml",
		KernelPath:   "/tmp/vmlinuz",
		InitrdPath:   "/tmp/initramfs",
		DHCPConfig: DHCPConfig{
			ServerIP:   "192.168.1.1",
			RangeStart: "192.168.1.100",
			RangeEnd:   "192.168.1.200",
			SubnetMask: "255.255.255.0",
		},
	}, testLogger())
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
	var target ErrManifestNotFound
	if !errors.As(err, &target) {
		t.Errorf("expected ErrManifestNotFound, got %T: %v", err, err)
	}
}

func TestExtractMACFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "colon separated with suffix",
			path:     "/boot/device/aa:bb:cc:dd:ee:ff.ipxe",
			expected: "aa:bb:cc:dd:ee:ff",
		},
		{
			name:     "dash separated with suffix",
			path:     "/boot/device/aa-bb-cc-dd-ee-ff.ipxe",
			expected: "aa:bb:cc:dd:ee:ff",
		},
		{
			name:     "no suffix",
			path:     "/boot/device/aa:bb:cc:dd:ee:ff",
			expected: "aa:bb:cc:dd:ee:ff",
		},
		{
			name:     "empty",
			path:     "/boot/device/",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractMACFromPath(tc.path)
			if result != tc.expected {
				t.Errorf("extractMACFromPath(%q) = %q, want %q", tc.path, result, tc.expected)
			}
		})
	}
}
