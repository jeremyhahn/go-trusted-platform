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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const (
	// serverReadyTimeout bounds how long TestMain waits for the iPXE
	// server to bind every listener.
	serverReadyTimeout = 10 * time.Second

	// firmwareFixtureSize spans many 512-byte TFTP blocks and ends
	// mid-block, so a transfer that drops, repeats or truncates a block
	// changes the bytes the tests compare.
	firmwareFixtureSize = 256*1024 + 77

	// proxyUpstreamPath and proxyUpstreamBody are what the HTTPS origin
	// behind the /proxy/ route serves.
	proxyUpstreamPath = "/get"
	proxyUpstreamBody = `{"origin":"ipxe-suite-proxy-upstream"}`
)

// firmwareUpstreamPaths maps each path the TFTP server requests from its
// firmware upstream (boot.ipxe.org's layout, pkg/ipxe tftp_server.go) to
// the TFTP name it serves the binary under.
var firmwareUpstreamPaths = map[string]string{
	"/x86_64-efi/ipxe.efi":   "ipxe.efi",
	"/i386-efi/ipxe.efi":     "ipxe32.efi",
	"/undionly.kpxe":         "undionly.kpxe",
	"/arm64-efi/snponly.efi": ipxe.FirmwareSNPOnlyAArch64,
}

var (
	// testServer is the shared iPXE server for all tests
	testServer   *ipxe.Server
	testServerMu sync.RWMutex

	// testFirmwareUpstream stands in for boot.ipxe.org: the TFTP server
	// downloads its iPXE binaries from it when it starts.
	testFirmwareUpstream *httptest.Server

	// testFirmwareDir is the TFTP server's firmware cache. It is new and
	// empty on every run, so each run proves the download.
	testFirmwareDir string

	// testProxyUpstream is the HTTPS origin the /proxy/ route fetches
	// from; the iPXE server trusts its certificate and nothing else.
	testProxyUpstream *httptest.Server

	// testServerConfig holds the dynamically assigned ports
	testHTTPPort int
	testTFTPPort int
	testDHCPPort int // 0 unless IPXE_DHCP_ENABLED=1
	testServerIP = "127.0.0.1"
)

// TestMain starts the iPXE server (HTTP, TFTP and, when IPXE_DHCP_ENABLED=1,
// DHCP) and the two upstreams it reaches, runs the tests and tears it all
// down. A setup failure fails the run; nothing is skipped.
func TestMain(m *testing.M) {
	code := 1
	if err := setupSuite(); err != nil {
		fmt.Printf("iPXE suite setup failed: %v\n", err)
	} else {
		code = m.Run()
	}
	teardownSuite()
	os.Exit(code)
}

// setupSuite picks free ports, publishes them to the tests' environment,
// starts the stand-in upstreams and then the iPXE server.
func setupSuite() error {
	httpPort, err := findAvailablePort()
	if err != nil {
		return &SuiteSetupError{Step: "find HTTP port", Err: err}
	}
	testHTTPPort = httpPort

	tftpPort, err := findAvailableUDPPort()
	if err != nil {
		return &SuiteSetupError{Step: "find TFTP port", Err: err}
	}
	testTFTPPort = tftpPort

	env := map[string]string{
		EnvIPXEServerIP: testServerIP,
		EnvIPXEHTTPPort: strconv.Itoa(testHTTPPort),
		EnvIPXETFTPPort: strconv.Itoa(testTFTPPort),
	}
	if os.Getenv(EnvIPXEDHCPEnabled) == "1" {
		dhcpPort, err := findAvailableUDPPort()
		if err != nil {
			return &SuiteSetupError{Step: "find DHCP port", Err: err}
		}
		testDHCPPort = dhcpPort
		env[EnvIPXEDHCPPort] = strconv.Itoa(testDHCPPort)
	}
	for key, value := range env {
		if err := os.Setenv(key, value); err != nil {
			return &SuiteSetupError{Step: "set " + key, Err: err}
		}
	}

	firmwareDir, err := os.MkdirTemp("", "ipxe-suite-firmware-")
	if err != nil {
		return &SuiteSetupError{Step: "create firmware cache", Err: err}
	}
	testFirmwareDir = firmwareDir
	testFirmwareUpstream = httptest.NewServer(http.HandlerFunc(serveFirmwareFixture))
	testProxyUpstream = httptest.NewTLSServer(http.HandlerFunc(serveProxyFixture))

	return startTestServer()
}

// teardownSuite stops the iPXE server and the upstreams and removes the
// firmware cache.
func teardownSuite() {
	stopTestServer()
	if testFirmwareUpstream != nil {
		testFirmwareUpstream.Close()
	}
	if testProxyUpstream != nil {
		testProxyUpstream.Close()
	}
	if testFirmwareDir != "" {
		if err := os.RemoveAll(testFirmwareDir); err != nil {
			fmt.Printf("Error removing firmware cache %s: %v\n", testFirmwareDir, err)
		}
	}
}

// FirmwareFixture returns the bytes the firmware upstream serves for the
// TFTP name: a PE "MZ" header and a body unique to the name. The TFTP tests
// compare every download with it.
func FirmwareFixture(name string) []byte {
	seed := sha256.Sum256([]byte(name))
	data := make([]byte, firmwareFixtureSize)
	copy(data, "MZ")
	for i := 2; i < len(data); i++ {
		data[i] = seed[i%len(seed)] ^ byte(i)
	}
	return data
}

// serveFirmwareFixture is the firmware upstream's handler.
func serveFirmwareFixture(w http.ResponseWriter, r *http.Request) {
	name, ok := firmwareUpstreamPaths[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(FirmwareFixture(name)))
}

// serveProxyFixture is the proxy upstream's handler.
func serveProxyFixture(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != proxyUpstreamPath {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	http.ServeContent(w, r, "get.json", time.Time{}, bytes.NewReader([]byte(proxyUpstreamBody)))
}

// ProxyUpstreamURL returns the iPXE server's /proxy/ URL for the proxy
// upstream's path: /proxy/https/<host:port>/get.
func ProxyUpstreamURL(cfg TestServerConfig) string {
	return fmt.Sprintf("http://%s:%d/proxy/https/%s%s",
		cfg.ServerIP, cfg.HTTPPort, testProxyUpstream.Listener.Addr(), proxyUpstreamPath)
}

// startTestServer starts the iPXE test server and waits until every
// listener is bound.
func startTestServer() error {
	testServerMu.Lock()
	defer testServerMu.Unlock()

	logger := logging.DefaultLogger()

	proxyCAs := x509.NewCertPool()
	proxyCAs.AddCert(testProxyUpstream.Certificate())

	// Create server config
	cfg := &ipxe.ServerConfig{
		HTTPPort:         testHTTPPort,
		TFTPPort:         testTFTPPort,
		ExternalURL:      fmt.Sprintf("http://%s:%d", testServerIP, testHTTPPort),
		FirmwareDir:      testFirmwareDir,
		FirmwareUpstream: testFirmwareUpstream.URL,
		ProxyCACertPool:  proxyCAs,
		BootEntries: []ipxe.BootEntry{
			{
				Name:        "alpine-test",
				Description: "Alpine Linux Test Entry",
				ISOURL:      "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-standard-3.20.0-x86_64.iso",
			},
			{
				Name:        "test-kernel",
				Description: "Test Kernel Boot",
				Kernel:      "http://example.com/vmlinuz",
				Initrd:      "http://example.com/initrd.img",
				Args:        "console=ttyS0",
			},
		},
	}

	if testDHCPPort != 0 {
		// The DHCP server listens on a free high port on loopback, where
		// the tests' client reaches it; see DHCPTestInterface.
		cfg.EnableDHCP = true
		cfg.DHCPInterface = DHCPTestInterface
		cfg.DHCPPort = testDHCPPort
		cfg.DHCPServerIP = testServerIP
		cfg.DHCPRangeStart = DefaultDHCPRangeStart
		cfg.DHCPRangeEnd = DefaultDHCPRangeEnd
		cfg.DHCPSubnetMask = DefaultSubnetMask
		cfg.DHCPLeaseTime = time.Hour
	}

	server, err := ipxe.NewServer(cfg, logger)
	if err != nil {
		return &SuiteSetupError{Step: "create iPXE server", Err: err}
	}
	testServer = server

	// Start returns only when the server stops; an error before Ready
	// is a failed start. The buffer lets a later error land unread.
	startErr := make(chan error, 1)
	go func() {
		if err := server.Start(context.Background()); err != nil {
			startErr <- err
		}
	}()

	select {
	case <-server.Ready():
	case err := <-startErr:
		return &SuiteSetupError{Step: "start iPXE server", Err: err}
	case <-time.After(serverReadyTimeout):
		return &SuiteSetupError{Step: "wait for iPXE server", Err: ErrServerNotReady}
	}

	fmt.Printf("iPXE test server started on HTTP=%s:%d TFTP=%s:%d\n",
		testServerIP, testHTTPPort, testServerIP, testTFTPPort)

	return nil
}

// stopTestServer stops the iPXE test server.
func stopTestServer() {
	testServerMu.Lock()
	defer testServerMu.Unlock()

	if testServer != nil {
		if err := testServer.Stop(); err != nil {
			fmt.Printf("Error stopping test server: %v\n", err)
		}
		testServer = nil
	}
}

// findAvailablePort finds an available TCP port.
func findAvailablePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// findAvailableUDPPort returns a UDP port that is free on 0.0.0.0, where
// the DHCP and TFTP servers bind.
func findAvailableUDPPort() (int, error) {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port, nil
}
