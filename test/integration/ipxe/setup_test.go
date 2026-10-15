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
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

var (
	// testServer is the shared iPXE server for all tests
	testServer     *ipxe.Server
	testServerOnce sync.Once
	testServerMu   sync.RWMutex

	// testServerConfig holds the dynamically assigned ports
	testHTTPPort int
	testTFTPPort int
	testServerIP = "127.0.0.1"
)

// TestMain sets up and tears down the iPXE server for integration tests.
func TestMain(m *testing.M) {
	// Skip if not integration test
	if os.Getenv("INTEGRATION_TEST") == "" {
		fmt.Println("Skipping integration tests. Set INTEGRATION_TEST=1 to run.")
		os.Exit(0)
	}

	// Find available ports
	httpPort, err := findAvailablePort()
	if err != nil {
		fmt.Printf("Failed to find available HTTP port: %v\n", err)
		os.Exit(1)
	}
	testHTTPPort = httpPort

	tftpPort, err := findAvailablePort()
	if err != nil {
		fmt.Printf("Failed to find available TFTP port: %v\n", err)
		os.Exit(1)
	}
	testTFTPPort = tftpPort

	// Update environment for tests
	os.Setenv(EnvIPXEServerIP, testServerIP)
	os.Setenv(EnvIPXEHTTPPort, fmt.Sprintf("%d", testHTTPPort))
	os.Setenv(EnvIPXETFTPPort, fmt.Sprintf("%d", testTFTPPort))

	// Start the server
	if err := startTestServer(); err != nil {
		fmt.Printf("Failed to start test server: %v\n", err)
		os.Exit(1)
	}

	// Run tests
	code := m.Run()

	// Stop the server
	stopTestServer()

	os.Exit(code)
}

// startTestServer starts the iPXE server for testing.
func startTestServer() error {
	testServerMu.Lock()
	defer testServerMu.Unlock()

	logger := logging.DefaultLogger()

	// Create server config
	cfg := &ipxe.ServerConfig{
		HTTPPort:    testHTTPPort,
		TFTPPort:    testTFTPPort,
		EnableDHCP:  false, // DHCP requires root and special network setup
		ExternalURL: fmt.Sprintf("http://%s:%d", testServerIP, testHTTPPort),
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

	var err error
	testServer, err = ipxe.NewServer(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to create iPXE server: %w", err)
	}

	// Start server in background
	ctx := context.Background()
	go func() {
		if err := testServer.Start(ctx); err != nil {
			logger.Error(fmt.Errorf("iPXE server error: %w", err))
		}
	}()

	// Wait for server to be ready
	if err := waitForServerReady(); err != nil {
		return fmt.Errorf("server failed to become ready: %w", err)
	}

	fmt.Printf("iPXE test server started on HTTP=%s:%d TFTP=%s:%d\n",
		testServerIP, testHTTPPort, testServerIP, testTFTPPort)

	return nil
}

// stopTestServer stops the iPXE server.
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

// waitForServerReady waits for the server to be ready to accept connections.
func waitForServerReady() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Ready closes once the HTTP and TFTP listeners have both bound
	select {
	case <-testServer.Ready():
		return nil
	case <-ctx.Done():
		return &testenv.WaitTimeoutError{Condition: "iPXE server listeners bound", Err: ctx.Err()}
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

// GetTestHTTPBaseURL returns the HTTP base URL for the test server.
func GetTestHTTPBaseURL() string {
	return fmt.Sprintf("http://%s:%d", testServerIP, testHTTPPort)
}

// GetTestTFTPAddress returns the TFTP server address for tests.
func GetTestTFTPAddress() string {
	return fmt.Sprintf("%s:%d", testServerIP, testTFTPPort)
}

// GetTestServerIP returns the test server IP address.
func GetTestServerIP() string {
	return testServerIP
}
