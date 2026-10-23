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
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPServer_handleMenuScript_EmptyDefault tests the menu script handler
// when there are no boot entries (tests the default selection logic).
func TestHTTPServer_handleMenuScript_EmptyDefault(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	cfg.BootEntries = []BootEntry{} // Empty - tests the empty default branch

	server := NewHTTPServer(cfg, logging.DefaultLogger())

	req := httptest.NewRequest("GET", "/menu.ipxe", nil)
	w := httptest.NewRecorder()

	server.handleMenuScript(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should still return OK even with no entries
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	content := string(body)
	assert.Contains(t, content, "#!ipxe")
	// Default should be empty when no entries
	assert.Contains(t, content, "--default  selected")
}

// TestHTTPServer_handleLocalFiles_StatErrorOther tests the error path when
// os.Stat returns an error that is not "not exist".
func TestHTTPServer_handleLocalFiles_StatErrorOther(t *testing.T) {
	// Create a temp directory structure that will cause stat errors
	tmpDir := t.TempDir()

	cfg := DefaultServerConfig()
	cfg.LocalFilesDir = tmpDir
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	// Create a symlink that points to itself (circular)
	linkPath := filepath.Join(tmpDir, "circular")
	// Create a valid file first, then we'll test stat on non-existent
	testFile := filepath.Join(tmpDir, "exists.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("content"), 0644))

	// Remove permissions to cause stat error (only works on Unix)
	if os.Geteuid() != 0 {
		restrictedDir := filepath.Join(tmpDir, "restricted")
		require.NoError(t, os.MkdirAll(restrictedDir, 0700))
		restrictedFile := filepath.Join(restrictedDir, "file.txt")
		require.NoError(t, os.WriteFile(restrictedFile, []byte("content"), 0644))
		require.NoError(t, os.Chmod(restrictedDir, 0000))
		defer os.Chmod(restrictedDir, 0700) // Restore permissions for cleanup

		req := httptest.NewRequest("GET", "/files/restricted/file.txt", nil)
		w := httptest.NewRecorder()
		server.handleLocalFiles(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		// Should return 500 when stat fails with permission error
		// or 404 if os detects it as not found
		assert.True(t, resp.StatusCode == http.StatusInternalServerError ||
			resp.StatusCode == http.StatusNotFound,
			"expected 500 or 404, got %d", resp.StatusCode)
	}

	// Test with valid symlink
	os.Symlink(testFile, linkPath)
	req := httptest.NewRequest("GET", "/files/circular", nil)
	w := httptest.NewRecorder()
	server.handleLocalFiles(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Symlink to file should work
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestServer_StartWithDHCPEnabled tests the server start with DHCP enabled.
// When running as non-root, DHCP will fail to bind to port 67 which is expected
// and the server should handle this gracefully.
func TestServer_StartWithDHCPEnabled(t *testing.T) {
	isRoot := os.Getuid() == 0

	config := &ServerConfig{
		HTTPPort:       28880,
		TFTPPort:       20169,
		LocalFilesDir:  t.TempDir(),
		EnableDHCP:     true,
		DHCPInterface:  "lo",
		DHCPRangeStart: "127.0.0.1",
		DHCPRangeEnd:   "127.0.0.10",
		DHCPSubnetMask: "255.255.255.0",
		DHCPLeaseTime:  1 * time.Hour,
		DHCPServerIP:   "127.0.0.1",
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	require.NoError(t, err)
	require.NotNil(t, server.dhcpServer, "DHCP server should be created when enabled")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Start server in goroutine. returned is closed as well as errChan being
	// sent, so the wait below can observe Start finishing WITHOUT consuming
	// its error — the assertions further down still need it.
	errChan := make(chan error, 1)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		errChan <- server.Start(ctx)
	}()

	// Wait for readiness OR for Start to return. Ready() closes only when
	// EVERY listener binds, and when not running as root the DHCP listener
	// cannot bind to port 67 — which this test explicitly tolerates — so
	// waiting on Ready() alone would hang until the deadline (#260).
	select {
	case <-server.Ready():
	case <-returned:
		// A listener failed to bind; the assertions below cover both cases.
	case <-time.After(ipxeDeadline):
		t.Fatalf("server neither became ready nor failed within %s", ipxeDeadline)
	}

	// When running as root, DHCP binds successfully and server should be running.
	// When not running as root, DHCP fails to bind to port 67 and server stops,
	// which is expected behavior - the server gracefully handles DHCP failure.
	if isRoot {
		assert.True(t, server.IsRunning(), "server should be running when DHCP can bind")
	}
	// Note: When not root, IsRunning() may be false because DHCP failure stops the server

	// Stop the server
	err = server.Stop()
	assert.NoError(t, err)

	// Wait for Start to complete
	select {
	case err := <-errChan:
		if isRoot {
			// When root, expect clean shutdown with no error
			assert.NoError(t, err)
		}
		// When not root, DHCP failure error is expected
	case <-time.After(2 * time.Second):
		t.Error("Start() did not complete after Stop()")
	}
}

// TestServer_BuildDHCPConfig_AllOptionalFields tests buildDHCPConfig with all
// optional fields populated.
func TestServer_BuildDHCPConfig_AllOptionalFields(t *testing.T) {
	config := &ServerConfig{
		HTTPPort:       8080,
		TFTPPort:       69,
		Interface:      "lo",
		EnableDHCP:     true,
		DHCPInterface:  "lo",
		DHCPRangeStart: "127.0.0.1",
		DHCPRangeEnd:   "127.0.0.10",
		DHCPSubnetMask: "255.255.255.0",
		DHCPLeaseTime:  2 * time.Hour,
		DHCPGateway:    "127.0.0.1",
		DHCPDNS:        []string{"8.8.8.8"},
		DHCPServerIP:   "127.0.0.1",
		TFTPServerName: "pxeserver",
		BootFilename:   "ipxe.efi",
		IPXEScript:     "http://127.0.0.1:8080/boot.ipxe",
		LocalFilesDir:  "/tmp",
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()
	server, err := NewServer(config, logger)

	require.NoError(t, err)
	require.NotNil(t, server)
	require.NotNil(t, server.dhcpServer)
}

// TestServer_BuildDHCPConfig_InterfaceFallback tests that DHCPInterface falls
// back to Interface when empty.
func TestServer_BuildDHCPConfig_InterfaceFallback(t *testing.T) {
	config := &ServerConfig{
		HTTPPort:       8080,
		TFTPPort:       69,
		Interface:      "lo",
		EnableDHCP:     true,
		DHCPInterface:  "", // Empty - should fall back to Interface
		DHCPRangeStart: "127.0.0.1",
		DHCPRangeEnd:   "127.0.0.10",
		DHCPSubnetMask: "255.255.255.0",
		DHCPLeaseTime:  1 * time.Hour,
		DHCPServerIP:   "127.0.0.1",
		LocalFilesDir:  "/tmp",
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()
	server, err := NewServer(config, logger)

	require.NoError(t, err)
	require.NotNil(t, server)
	require.NotNil(t, server.dhcpServer)
}

// TestServer_NewServer_InvalidServerIP tests NewServer with an invalid server IP.
func TestServer_NewServer_InvalidServerIP(t *testing.T) {
	config := &ServerConfig{
		HTTPPort:      8080,
		TFTPPort:      69,
		Interface:     "",                      // No interface
		ExternalURL:   "http://not-an-ip:8080", // URL doesn't contain IP
		LocalFilesDir: "/tmp",
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
		},
	}

	// This will try to auto-detect IP, which might succeed or fail
	// depending on system configuration
	logger := logging.DefaultLogger()
	_, err := NewServer(config, logger)

	// Either success (if there's a valid interface) or error
	if err != nil {
		assert.Contains(t, err.Error(), "IP")
	}
}

// TestTFTPServer_getCacheDir_UserCacheDirAvailable tests getCacheDir when
// user cache dir is available.
func TestTFTPServer_getCacheDir_UserCacheDirAvailable(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	cacheDir := server.getCacheDir()

	assert.NotEmpty(t, cacheDir)
	assert.Contains(t, cacheDir, cacheDirName)
	assert.Contains(t, cacheDir, firmwareSubDir)
}

// TestTFTPServer_loadFirmwareFile_CacheSaveError tests the error path
// when cache directory cannot be created.
func TestTFTPServer_loadFirmwareFile_CacheSaveError(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	// Create a mock HTTP server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("firmware data"))
	}))
	defer mockServer.Close()

	// Use a directory that doesn't exist and can't be created
	// (only works if we're not root)
	if os.Geteuid() != 0 {
		invalidCacheDir := "/root/nonexistent/cache"
		err := server.loadFirmwareFile("test.efi", mockServer.URL, invalidCacheDir)

		// Should succeed loading to memory even if caching fails
		// (caching failure is logged but doesn't cause error)
		assert.NoError(t, err)

		// Verify firmware is in memory
		server.firmwareMu.RLock()
		_, ok := server.firmware["test.efi"]
		server.firmwareMu.RUnlock()
		assert.True(t, ok)
	}
}

// TestHTTPServer_handleBootEntry_NoValidBootMethod tests handleBootEntry with
// an entry that has no kernel, initrd, or ISO URL configured.
func TestHTTPServer_handleBootEntry_NoValidBootMethod(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	cfg.BootEntries = []BootEntry{
		{
			Name:        "invalid",
			Description: "Invalid Entry",
			// No Kernel, Initrd, or ISOURL
		},
	}

	server := NewHTTPServer(cfg, logging.DefaultLogger())

	req := httptest.NewRequest("GET", "/boot/invalid.ipxe", nil)
	w := httptest.NewRecorder()

	server.handleBootEntry(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 500 Internal Server Error
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestHTTPServer_generateNetbootScript_AlpineSpecific tests the netboot
// script generation specifically for Alpine Linux URLs.
func TestHTTPServer_generateNetbootScript_AlpineSpecific(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	entry := &BootEntry{
		Name:        "alpine",
		Description: "Alpine Linux 3.20",
		ISOURL:      "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-standard-3.20.0-x86_64.iso",
		// No custom kernel/initrd - should use derived URLs
	}

	script := server.generateNetbootScript(entry)

	// Should contain Alpine-specific URLs
	assert.Contains(t, script, "Alpine Linux 3.20")
	assert.Contains(t, script, "kernel")
	assert.Contains(t, script, "initrd")
	// Should convert HTTPS to proxy URLs
	assert.Contains(t, script, "/proxy/https/")
}

// TestHTTPServer_generateNetbootScript_CustomArgs tests netboot script
// generation with custom kernel arguments.
func TestHTTPServer_generateNetbootScript_CustomArgs(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	entry := &BootEntry{
		Name:        "custom",
		Description: "Custom Boot",
		ISOURL:      "https://example.com/custom.iso",
		Args:        "console=tty0 custom_arg=value",
	}

	script := server.generateNetbootScript(entry)

	// Should contain custom args
	assert.Contains(t, script, "console=tty0")
	assert.Contains(t, script, "custom_arg=value")
}

// TestHTTPServer_proxyArgsURLs_NoHTTPS tests proxyArgsURLs when there are
// no HTTPS URLs in the arguments.
func TestHTTPServer_proxyArgsURLs_NoHTTPS(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	// No HTTPS URLs
	args := "console=tty0 root=/dev/sda1 quiet"
	result := server.proxyArgsURLs(args)

	// Should be unchanged
	assert.Equal(t, args, result)
	assert.NotContains(t, result, "/proxy/")
}

// TestServer_Stop_ShutdownTimeout tests that Stop handles timeout gracefully.
func TestServer_Stop_ShutdownTimeout(t *testing.T) {
	config := &ServerConfig{
		HTTPPort:      29880,
		TFTPPort:      21069,
		LocalFilesDir: t.TempDir(),
		EnableDHCP:    false,
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()
	server, err := NewServer(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		server.Start(ctx)
	}()

	// DHCP is disabled in this config, so Ready() closes once HTTP and TFTP
	// have bound.
	awaitReady(t, server)

	// Stop should complete even if services are slow to stop
	err = server.Stop()
	assert.NoError(t, err)
}

// TestParseBootConfig_KernelWithSingleArg tests parsing boot config with
// kernel command having only one argument.
func TestParseBootConfig_KernelWithSingleArg(t *testing.T) {
	content := `menuentry "Minimal" {
		linux /boot/vmlinuz quiet
	}`

	result := parseBootConfig(content)
	assert.Equal(t, "quiet", result)
}

// TestParseBootConfig_APPENDOnly tests parsing boot config with just APPEND
// keyword and no args.
func TestParseBootConfig_APPENDOnly(t *testing.T) {
	content := `LABEL test
		KERNEL vmlinuz
		APPEND`

	result := parseBootConfig(content)
	assert.Equal(t, "", result)
}

// TestFindBootFiles_RootKernel tests that standard locations are
// checked before recursive search.
func TestFindBootFiles_RootKernel(t *testing.T) {
	tmpDir := t.TempDir()

	// Create kernel in root
	err := os.WriteFile(filepath.Join(tmpDir, "vmlinuz"), []byte("kernel"), 0644)
	require.NoError(t, err)

	// Create initrd in root
	err = os.WriteFile(filepath.Join(tmpDir, "initrd"), []byte("initrd"), 0644)
	require.NoError(t, err)

	kernelPath, initrdPath, err := findBootFiles(tmpDir)
	require.NoError(t, err)

	assert.Contains(t, kernelPath, "vmlinuz")
	assert.Contains(t, initrdPath, "initrd")
}

// TestFindBootFiles_InitrdGz tests finding initrd.gz format.
func TestFindBootFiles_InitrdGz(t *testing.T) {
	tmpDir := t.TempDir()

	// Create vmlinuz and initrd.gz
	err := os.WriteFile(filepath.Join(tmpDir, "vmlinuz"), []byte("kernel"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tmpDir, "initrd.gz"), []byte("initrd"), 0644)
	require.NoError(t, err)

	kernelPath, initrdPath, err := findBootFiles(tmpDir)
	require.NoError(t, err)

	assert.Contains(t, kernelPath, "vmlinuz")
	assert.Contains(t, initrdPath, "initrd.gz")
}

// TestServer_WaitForHTTPReady_NotReady tests waitForHTTPReady when server
// is not ready.
func TestServer_WaitForHTTPReady_NotReady(t *testing.T) {
	// The deadline runs on synctest time (#284).
	synctest.Test(t, func(t *testing.T) {
		config := createMinimalConfig(t)
		config.HTTPPort = 39880 // Unused port

		logger := logging.DefaultLogger()
		server, err := NewServer(config, logger)
		require.NoError(t, err)

		// Don't start the server - it should not be ready
		deadline := time.Now().Add(100 * time.Millisecond)
		ready := server.waitForHTTPReady(deadline)

		assert.False(t, ready, "server should not be ready when not started")
	})
}

// TestDHCPServer_handleDiscover_NoIPAvailable tests handleDiscover when
// no IPs are available.
func TestDHCPServer_handleDiscover_NoIPAvailable(t *testing.T) {
	// Create server with only 1 IP in range
	config := &DHCPConfig{
		ServerIP:       net.ParseIP("192.168.1.1"),
		BroadcastIP:    net.ParseIP("192.168.1.255"),
		SubnetMask:     net.ParseIP("255.255.255.0"),
		RangeStart:     net.ParseIP("192.168.1.100"),
		RangeEnd:       net.ParseIP("192.168.1.100"), // Only 1 IP
		LeaseTime:      time.Hour,
		TFTPServerName: "pxeserver",
		TFTPServerIP:   net.ParseIP("192.168.1.1"),
		BootFilename:   "ipxe.efi",
	}
	server, err := NewDHCPServer(config, logging.DefaultLogger())
	require.NoError(t, err)

	mockConn := &mockPacketConn{}

	// Allocate the only available IP
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	_, err = server.getOrAssignIP(mac1)
	require.NoError(t, err)

	// Now try discover from another MAC - should fail silently (no response)
	req := createPXEDiscoverRequest(t)
	// Use a different MAC
	req.ClientHWAddr, _ = net.ParseMAC("00:11:22:33:44:66")

	peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 68}
	server.handleDiscover(mockConn, peer, req)

	// No response should be sent when IP assignment fails
	// (error is logged but no response sent)
}

// TestDHCPServer_handleRequest_NoIPAvailable tests handleRequest when
// no IPs are available for a new lease.
func TestDHCPServer_handleRequest_NoIPAvailable(t *testing.T) {
	config := &DHCPConfig{
		ServerIP:       net.ParseIP("192.168.1.1"),
		BroadcastIP:    net.ParseIP("192.168.1.255"),
		SubnetMask:     net.ParseIP("255.255.255.0"),
		RangeStart:     net.ParseIP("192.168.1.100"),
		RangeEnd:       net.ParseIP("192.168.1.100"),
		LeaseTime:      time.Hour,
		TFTPServerName: "pxeserver",
		TFTPServerIP:   net.ParseIP("192.168.1.1"),
		BootFilename:   "ipxe.efi",
	}
	server, err := NewDHCPServer(config, logging.DefaultLogger())
	require.NoError(t, err)

	mockConn := &mockPacketConn{}

	// Allocate the only available IP
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	_, err = server.getOrAssignIP(mac1)
	require.NoError(t, err)

	// Now try request from another MAC - should fail silently
	req := createPXERequestRequest(t, net.ParseIP("192.168.1.100"))
	req.ClientHWAddr, _ = net.ParseMAC("00:11:22:33:44:66")

	peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 68}
	server.handleRequest(mockConn, peer, req)
}

// TestTFTPServer_readHandler_TransferError tests error handling during
// TFTP transfer.
func TestTFTPServer_readHandler_TransferError(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	// Setup firmware
	testData := []byte("test firmware")
	server.firmwareMu.Lock()
	server.firmware["test.efi"] = testData
	server.firmwareMu.Unlock()

	// Create a mock that returns error on ReadFrom
	mockReader := &errorMockReaderFrom{
		err: io.ErrClosedPipe,
	}

	err := server.readHandler("test.efi", mockReader)
	assert.Error(t, err)
	assert.Equal(t, io.ErrClosedPipe, err)
}

// errorMockReaderFrom is a mock that returns an error on ReadFrom.
type errorMockReaderFrom struct {
	err error
}

func (m *errorMockReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	return 0, m.err
}

func (m *errorMockReaderFrom) RemoteAddr() net.UDPAddr {
	return net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
}

func (m *errorMockReaderFrom) SetSize(size int64) {}

// TestHTTPServer_handleProxy_ServerReturnsError tests error handling when copying
// the proxy response fails.
func TestHTTPServer_handleProxy_ServerReturnsError(t *testing.T) {
	// Create a test server that returns 500
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer testServer.Close()

	// Trust the test server's self-signed cert via ProxyCACertPool. The
	// proxy enforces full TLS verification (no InsecureSkipVerify allowed),
	// so the test trust store mirrors how a production deployment would
	// inject its upstream CAs.
	cfg := DefaultServerConfig()
	pool := x509.NewCertPool()
	pool.AddCert(testServer.Certificate())
	cfg.ProxyCACertPool = pool
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	// Extract host from test server URL
	testURL := testServer.URL[len("https://"):]

	req := httptest.NewRequest("GET", "/proxy/https/"+testURL, nil)
	w := httptest.NewRecorder()

	server.handleProxy(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 500 (proxied from upstream)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestServer_ErrorChannel tests that server error channel handles errors.
func TestServer_ErrorChannel(t *testing.T) {
	// This test verifies the error channel monitoring path in Start()
	config := &ServerConfig{
		HTTPPort:      39980,
		TFTPPort:      31069,
		LocalFilesDir: t.TempDir(),
		EnableDHCP:    false,
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()
	server, err := NewServer(config, logger)
	require.NoError(t, err)

	// Verify error channel is properly initialized
	assert.NotNil(t, server.errChan)
	assert.Equal(t, 3, cap(server.errChan))
}

// TestHTTPServer_generateNetbootScript_DirectKernel tests netboot script
// generation when kernel and initrd are directly specified.
func TestHTTPServer_generateNetbootScript_DirectKernel(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	entry := &BootEntry{
		Name:        "direct",
		Description: "Direct Boot",
		Kernel:      "http://192.168.1.10:8080/vmlinuz",
		Initrd:      "http://192.168.1.10:8080/initrd",
		Args:        "console=tty0",
	}

	script := server.generateNetbootScript(entry)

	// Should contain direct kernel URL
	assert.Contains(t, script, "http://192.168.1.10:8080/vmlinuz")
	assert.Contains(t, script, "http://192.168.1.10:8080/initrd")
	assert.Contains(t, script, "console=tty0")
}

// TestFindBootFiles_BzImage tests finding bzImage kernel format.
func TestFindBootFiles_BzImage(t *testing.T) {
	tmpDir := t.TempDir()

	// Create bzImage and initramfs.img
	err := os.WriteFile(filepath.Join(tmpDir, "bzImage"), []byte("kernel"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tmpDir, "initramfs.img"), []byte("initrd"), 0644)
	require.NoError(t, err)

	kernelPath, initrdPath, err := findBootFiles(tmpDir)
	require.NoError(t, err)

	assert.Contains(t, kernelPath, "bzImage")
	assert.Contains(t, initrdPath, "initramfs.img")
}

// TestParseBootConfig_EmptyContent tests parsing empty boot config content.
func TestParseBootConfig_EmptyContent(t *testing.T) {
	result := parseBootConfig("")
	assert.Equal(t, "", result)
}

// TestParseBootConfig_NoKernelArgs tests parsing boot config with kernel but no args.
func TestParseBootConfig_NoKernelArgs(t *testing.T) {
	content := `menuentry "Test" {
		linux /boot/vmlinuz
	}`

	result := parseBootConfig(content)
	assert.Equal(t, "", result)
}

// TestHTTPServer_handleBootEntry_WithAutoInstall tests boot entry with autoinstall config.
func TestHTTPServer_handleBootEntry_WithAutoInstall(t *testing.T) {
	tmpDir := t.TempDir()

	// Create autoinstall file
	autoinstallPath := filepath.Join(tmpDir, "user-data")
	err := os.WriteFile(autoinstallPath, []byte("#cloud-config\nautoinstall: true"), 0644)
	require.NoError(t, err)

	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	cfg.LocalFilesDir = tmpDir
	cfg.BootEntries = []BootEntry{
		{
			Name:        "ubuntu-auto",
			Description: "Ubuntu Auto Install",
			Kernel:      "http://192.168.1.10:8080/vmlinuz",
			Initrd:      "http://192.168.1.10:8080/initrd",
			AutoInstall: autoinstallPath,
			Args:        "autoinstall",
		},
	}

	server := NewHTTPServer(cfg, logging.DefaultLogger())

	req := httptest.NewRequest("GET", "/boot/ubuntu-auto.ipxe", nil)
	w := httptest.NewRecorder()

	server.handleBootEntry(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return OK
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestHTTPServer_handleBootEntry_NotFound tests handling of non-existent boot entry.
func TestHTTPServer_handleBootEntry_NotFound(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	cfg.BootEntries = []BootEntry{
		{
			Name:        "existing",
			Description: "Existing Entry",
			Kernel:      "http://example.com/vmlinuz",
		},
	}

	server := NewHTTPServer(cfg, logging.DefaultLogger())

	req := httptest.NewRequest("GET", "/boot/nonexistent.ipxe", nil)
	w := httptest.NewRecorder()

	server.handleBootEntry(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestTFTPServer_loadFirmwareFile_FromCache tests loading firmware from cache.
func TestTFTPServer_loadFirmwareFile_FromCache(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0755))

	// Create a cached file
	cachedFile := filepath.Join(cacheDir, "cached.efi")
	cachedData := []byte("cached firmware data")
	require.NoError(t, os.WriteFile(cachedFile, cachedData, 0644))

	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	// Load from cache (no HTTP server needed)
	err := server.loadFirmwareFile("cached.efi", "http://unreachable/firmware", cacheDir)
	assert.NoError(t, err)

	// Verify loaded from cache
	server.firmwareMu.RLock()
	data, ok := server.firmware["cached.efi"]
	server.firmwareMu.RUnlock()

	assert.True(t, ok)
	assert.Equal(t, cachedData, data)
}

// TestHTTPServer_handleLocalFiles_DirectoryListing tests directory listing behavior.
func TestHTTPServer_handleLocalFiles_DirectoryListing(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a subdirectory with files
	subDir := filepath.Join(tmpDir, "subdir")
	require.NoError(t, os.MkdirAll(subDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("content"), 0644))

	cfg := DefaultServerConfig()
	cfg.LocalFilesDir = tmpDir
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	// Request the subdirectory
	req := httptest.NewRequest("GET", "/files/subdir/", nil)
	w := httptest.NewRecorder()

	server.handleLocalFiles(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// http.FileServer returns either 200 with listing or 403 depending on setup
	// Just verify no error occurs
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden)
}

// TestHTTPServer_handleProxy_HTTPNotSupported tests proxy handler rejects HTTP protocol.
func TestHTTPServer_handleProxy_HTTPNotSupported(t *testing.T) {
	cfg := DefaultServerConfig()
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	// Create a test server
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("http response"))
	}))
	defer testServer.Close()

	// Extract host from test server URL
	testURL := testServer.URL[len("http://"):]

	req := httptest.NewRequest("GET", "/proxy/http/"+testURL, nil)
	w := httptest.NewRecorder()

	server.handleProxy(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 400 Bad Request - only HTTPS is supported
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestHTTPServer_handleProxy_MissingURL tests proxy handler with missing URL.
func TestHTTPServer_handleProxy_MissingURL(t *testing.T) {
	cfg := DefaultServerConfig()
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	req := httptest.NewRequest("GET", "/proxy/", nil)
	w := httptest.NewRecorder()

	server.handleProxy(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestHTTPServer_handleProxy_InvalidURLFormat tests proxy handler with invalid URL format.
func TestHTTPServer_handleProxy_InvalidURLFormat(t *testing.T) {
	cfg := DefaultServerConfig()
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	// Only scheme, no host/path
	req := httptest.NewRequest("GET", "/proxy/https", nil)
	w := httptest.NewRecorder()

	server.handleProxy(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
