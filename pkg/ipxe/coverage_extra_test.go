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
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDHCPServer_WithIPXEScript tests DHCP server with iPXE script configured.
func TestDHCPServer_WithIPXEScript(t *testing.T) {
	config := &DHCPConfig{
		ServerIP:       net.ParseIP("192.168.1.1"),
		BroadcastIP:    net.ParseIP("192.168.1.255"),
		SubnetMask:     net.ParseIP("255.255.255.0"),
		RangeStart:     net.ParseIP("192.168.1.100"),
		RangeEnd:       net.ParseIP("192.168.1.200"),
		LeaseTime:      time.Hour,
		TFTPServerName: "pxeserver",
		TFTPServerIP:   net.ParseIP("192.168.1.1"),
		BootFilename:   "ipxe.efi",
		IPXEScript:     "http://192.168.1.1:8080/boot.ipxe",
	}

	server, err := NewDHCPServer(config, logging.DefaultLogger())
	require.NoError(t, err)
	assert.NotNil(t, server)
}

// TestDHCPServer_WithRouterAndDNS tests DHCP server with router and DNS configured.
func TestDHCPServer_WithRouterAndDNS(t *testing.T) {
	config := &DHCPConfig{
		ServerIP:       net.ParseIP("192.168.1.1"),
		BroadcastIP:    net.ParseIP("192.168.1.255"),
		SubnetMask:     net.ParseIP("255.255.255.0"),
		RangeStart:     net.ParseIP("192.168.1.100"),
		RangeEnd:       net.ParseIP("192.168.1.200"),
		LeaseTime:      time.Hour,
		Router:         net.ParseIP("192.168.1.254"),
		DNSServers:     []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		TFTPServerName: "pxeserver",
		TFTPServerIP:   net.ParseIP("192.168.1.1"),
		BootFilename:   "ipxe.efi",
	}

	server, err := NewDHCPServer(config, logging.DefaultLogger())
	require.NoError(t, err)
	assert.NotNil(t, server)
}

// TestDHCPServer_isIPXEClient_WithIPXEUserClass tests iPXE client detection.
func TestDHCPServer_isIPXEClient_WithIPXEUserClass(t *testing.T) {
	config := &DHCPConfig{
		ServerIP:     net.ParseIP("192.168.1.1"),
		BroadcastIP:  net.ParseIP("192.168.1.255"),
		SubnetMask:   net.ParseIP("255.255.255.0"),
		RangeStart:   net.ParseIP("192.168.1.100"),
		RangeEnd:     net.ParseIP("192.168.1.200"),
		LeaseTime:    time.Hour,
		BootFilename: "ipxe.efi",
	}

	server, err := NewDHCPServer(config, logging.DefaultLogger())
	require.NoError(t, err)

	// Create a request with iPXE user class
	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	require.NoError(t, err)

	// Add iPXE user class option
	req.UpdateOption(dhcpv4.OptUserClass("iPXE"))

	result := server.isIPXEClient(req)
	assert.True(t, result, "should detect iPXE client by user class")
}

// TestTFTPServer_loadFirmware_EmptyConfig tests TFTP server with minimal config.
func TestTFTPServer_loadFirmware_EmptyConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &ServerConfig{
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
		},
	}
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	// Verify server was created
	assert.NotNil(t, server)
}

// TestHTTPServer_handleLocalFiles_NotExist tests requesting a non-existent file.
func TestHTTPServer_handleLocalFiles_NotExist(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := DefaultServerConfig()
	cfg.LocalFilesDir = tmpDir
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	req := httptest.NewRequest("GET", "/files/nonexistent.txt", nil)
	w := httptest.NewRecorder()

	server.handleLocalFiles(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestHTTPServer_generateNetbootScript_HTTPSKernel tests netboot script
// generation with HTTPS kernel URL.
func TestHTTPServer_generateNetbootScript_HTTPSKernel(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	entry := &BootEntry{
		Name:        "https-kernel",
		Description: "HTTPS Kernel Test",
		Kernel:      "https://example.com/vmlinuz",
		Initrd:      "https://example.com/initrd",
	}

	script := server.generateNetbootScript(entry)

	// HTTPS kernel should be proxied
	assert.Contains(t, script, "/proxy/https/")
}

// TestParseBootConfig_GrubConfig tests parsing GRUB2 config format.
func TestParseBootConfig_GrubConfig(t *testing.T) {
	content := `
	menuentry 'Ubuntu Server' {
		linux /boot/vmlinuz root=UUID=abc quiet splash
		initrd /boot/initrd.img
	}`

	result := parseBootConfig(content)
	assert.Contains(t, result, "root=UUID=abc")
	assert.Contains(t, result, "quiet")
	assert.Contains(t, result, "splash")
}

// TestParseBootConfig_SyslinuxConfig tests parsing Syslinux config format.
func TestParseBootConfig_SyslinuxConfig(t *testing.T) {
	content := `
LABEL linux
  KERNEL vmlinuz
  APPEND initrd=initrd.img root=/dev/sda1 console=tty0
`

	result := parseBootConfig(content)
	assert.Contains(t, result, "root=/dev/sda1")
	assert.Contains(t, result, "console=tty0")
}

// TestFindBootFiles_NestedDirectory tests finding boot files in nested directories.
func TestFindBootFiles_NestedDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested boot directory
	bootDir := filepath.Join(tmpDir, "boot", "current")
	require.NoError(t, os.MkdirAll(bootDir, 0755))

	// Create kernel and initrd in nested directory
	require.NoError(t, os.WriteFile(filepath.Join(bootDir, "vmlinuz"), []byte("kernel"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(bootDir, "initrd.img"), []byte("initrd"), 0644))

	kernelPath, initrdPath, err := findBootFiles(tmpDir)
	require.NoError(t, err)

	assert.Contains(t, kernelPath, "vmlinuz")
	assert.Contains(t, initrdPath, "initrd.img")
}

// TestFindBootFiles_NoInitrd tests finding boot files when only kernel exists.
// The function requires both kernel and initrd to be present.
func TestFindBootFiles_NoInitrd(t *testing.T) {
	tmpDir := t.TempDir()

	// Create only kernel (no initrd)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "vmlinuz"), []byte("kernel"), 0644))

	_, _, err := findBootFiles(tmpDir)

	// Should return an error because initrd is required
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "initrd file not found")
}

// TestFindBootFiles_NoKernel tests finding boot files when only initrd exists.
// The function requires both kernel and initrd to be present.
func TestFindBootFiles_NoKernel(t *testing.T) {
	tmpDir := t.TempDir()

	// Create only initrd (no kernel)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "initrd.img"), []byte("initrd"), 0644))

	_, _, err := findBootFiles(tmpDir)

	// Should return an error because kernel is required
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kernel file not found")
}

// TestDHCPServer_CleanupExpiredLeases tests that expired leases are cleaned up.
func TestDHCPServer_CleanupExpiredLeases(t *testing.T) {
	config := &DHCPConfig{
		ServerIP:     net.ParseIP("192.168.1.1"),
		BroadcastIP:  net.ParseIP("192.168.1.255"),
		SubnetMask:   net.ParseIP("255.255.255.0"),
		RangeStart:   net.ParseIP("192.168.1.100"),
		RangeEnd:     net.ParseIP("192.168.1.110"),
		LeaseTime:    100 * time.Millisecond, // Very short lease
		BootFilename: "ipxe.efi",
	}

	server, err := NewDHCPServer(config, logging.DefaultLogger())
	require.NoError(t, err)

	// Allocate an IP
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip, err := server.getOrAssignIP(mac)
	require.NoError(t, err)
	assert.NotNil(t, ip)

	// Wait for lease to expire
	time.Sleep(150 * time.Millisecond)

	// Allocate again - should work because lease expired
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	ip2, err := server.getOrAssignIP(mac2)
	require.NoError(t, err)
	assert.NotNil(t, ip2)
}

// TestHTTPServer_handleBootScript_ValidContent tests the boot script handler.
func TestHTTPServer_handleBootScript_ValidContent(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	cfg.BootEntries = []BootEntry{
		{
			Name:        "ubuntu",
			Description: "Ubuntu Server",
			Kernel:      "http://192.168.1.10:8080/vmlinuz",
			Initrd:      "http://192.168.1.10:8080/initrd",
		},
	}

	server := NewHTTPServer(cfg, logging.DefaultLogger())

	req := httptest.NewRequest("GET", "/boot.ipxe", nil)
	w := httptest.NewRecorder()

	server.handleBootScript(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
}

// TestHTTPServer_handleMenuScript_WithMultipleEntries tests menu with multiple entries.
func TestHTTPServer_handleMenuScript_WithMultipleEntries(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	cfg.BootEntries = []BootEntry{
		{Name: "ubuntu", Description: "Ubuntu Server", Kernel: "http://example.com/ubuntu/vmlinuz"},
		{Name: "debian", Description: "Debian Server", Kernel: "http://example.com/debian/vmlinuz"},
		{Name: "alpine", Description: "Alpine Linux", ISOURL: "https://example.com/alpine.iso"},
	}

	server := NewHTTPServer(cfg, logging.DefaultLogger())

	req := httptest.NewRequest("GET", "/menu.ipxe", nil)
	w := httptest.NewRecorder()

	server.handleMenuScript(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestTFTPServer_readHandler_FileNotFound tests TFTP read handler with missing file.
func TestTFTPServer_readHandler_FileNotFound(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	// Don't add any firmware

	mockReader := &errorMockReaderFrom{}

	err := server.readHandler("nonexistent.efi", mockReader)
	assert.Error(t, err)
	// Use errors.Is because the error is wrapped with fmt.Errorf("%w: %s", ...)
	assert.True(t, errors.Is(err, ErrFirmwareNotFound), "error should wrap ErrFirmwareNotFound")
}

// TestHTTPServer_proxyArgsURLs_MultipleHTTPS tests proxying multiple HTTPS URLs.
func TestHTTPServer_proxyArgsURLs_MultipleHTTPS(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ExternalURL = "http://192.168.1.10:8080"
	server := NewHTTPServer(cfg, logging.DefaultLogger())

	args := "url1=https://example.com/file1 url2=https://test.com/file2 normal_arg=value"
	result := server.proxyArgsURLs(args)

	// Both HTTPS URLs should be proxied
	assert.Contains(t, result, "/proxy/https/example.com/file1")
	assert.Contains(t, result, "/proxy/https/test.com/file2")
	assert.Contains(t, result, "normal_arg=value")
}

// TestDHCPServer_isIPXEClient_WithoutUserClass tests iPXE detection without user class.
func TestDHCPServer_isIPXEClient_WithoutUserClass(t *testing.T) {
	config := &DHCPConfig{
		ServerIP:     net.ParseIP("192.168.1.1"),
		BroadcastIP:  net.ParseIP("192.168.1.255"),
		SubnetMask:   net.ParseIP("255.255.255.0"),
		RangeStart:   net.ParseIP("192.168.1.100"),
		RangeEnd:     net.ParseIP("192.168.1.200"),
		LeaseTime:    time.Hour,
		BootFilename: "ipxe.efi",
	}

	server, err := NewDHCPServer(config, logging.DefaultLogger())
	require.NoError(t, err)

	// Create a request without iPXE user class
	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	require.NoError(t, err)

	result := server.isIPXEClient(req)
	assert.False(t, result, "should not detect iPXE client without user class")
}
