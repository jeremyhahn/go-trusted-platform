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

package helpers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// TestWriteLocalCLIConfigSelectsTheHarnessSocket parses the written file with
// platformctl's own loader. A file the loader cannot use falls back to the
// default context and /run/platformd.sock, which the harness never creates;
// that is how the CLI adapters reached no daemon (#540, #730).
func TestWriteLocalCLIConfigSelectsTheHarnessSocket(t *testing.T) {
	socketPath := "/tmp/platformd-test.sock"
	grpcAddr := "localhost:10443"

	path, err := WriteLocalCLIConfig(t.TempDir(), socketPath, grpcAddr)
	if err != nil {
		t.Fatalf("WriteLocalCLIConfig: %v", err)
	}

	local := loadHarnessLocalContext(t, path)
	if local.SocketPath != socketPath {
		t.Errorf("socket path = %q, want the harness socket %q", local.SocketPath, socketPath)
	}
	if local.GRPCAddr != grpcAddr {
		t.Errorf("gRPC address = %q, want %q", local.GRPCAddr, grpcAddr)
	}
}

// TestWriteLocalCLIConfigPointsQuicBaaSAtPlatformdOverTLS verifies the
// quicbaas connection goes to platformd's gRPC listener with the harness
// mTLS files: the quicbaas SDK refuses every transport without TLS, and
// platformd's Unix socket serves none.
func TestWriteLocalCLIConfigPointsQuicBaaSAtPlatformdOverTLS(t *testing.T) {
	t.Setenv(EnvCACert, "/certs/ca.crt")
	t.Setenv(EnvClientCert, "/certs/client.crt")
	t.Setenv(EnvClientKey, "/certs/client.key")
	grpcAddr := "localhost:10443"

	path, err := WriteLocalCLIConfig(t.TempDir(), "/tmp/platformd-test.sock", grpcAddr)
	if err != nil {
		t.Fatalf("WriteLocalCLIConfig: %v", err)
	}

	local := loadHarnessLocalContext(t, path)
	if local.QuicBaaSAddr != grpcAddr || local.QuicBaaSTransport != "grpc" {
		t.Errorf("quicbaas = %q over %q, want %q over grpc", local.QuicBaaSAddr, local.QuicBaaSTransport, grpcAddr)
	}
	if local.QuicBaaSCACert != "/certs/ca.crt" ||
		local.QuicBaaSClientCert != "/certs/client.crt" ||
		local.QuicBaaSClientKey != "/certs/client.key" {
		t.Errorf("quicbaas TLS files = %q, %q, %q, want the harness mTLS files",
			local.QuicBaaSCACert, local.QuicBaaSClientCert, local.QuicBaaSClientKey)
	}
}

// TestWriteLocalCLIConfigLeavesQuicBaaSUnsetWithoutGRPCAddr verifies an
// empty gRPC address writes no quicbaas connection and no TLS files, so the
// context does not point quicbaas at an empty address.
func TestWriteLocalCLIConfigLeavesQuicBaaSUnsetWithoutGRPCAddr(t *testing.T) {
	t.Setenv(EnvCACert, "/certs/ca.crt")

	path, err := WriteLocalCLIConfig(t.TempDir(), "/tmp/platformd-test.sock", "")
	if err != nil {
		t.Fatalf("WriteLocalCLIConfig: %v", err)
	}

	local := loadHarnessLocalContext(t, path)
	if local.QuicBaaSAddr != "" || local.QuicBaaSTransport != "" || local.QuicBaaSCACert != "" {
		t.Errorf("quicbaas = %q over %q (ca %q), want none", local.QuicBaaSAddr, local.QuicBaaSTransport, local.QuicBaaSCACert)
	}
}

// loadHarnessLocalContext loads the config at path through platformctl's own
// loader and returns its current context, which must be the local harness one.
func loadHarnessLocalContext(t *testing.T, path string) *cli.LocalContext {
	t.Helper()
	config, err := cli.LoadConfig(path)
	if err != nil {
		t.Fatalf("platformctl cannot load the written config: %v", err)
	}
	if config.CurrentContext != CLIContextName {
		t.Fatalf("current context = %q, want %q", config.CurrentContext, CLIContextName)
	}
	current, err := config.GetCurrentContext()
	if err != nil {
		t.Fatalf("resolve current context: %v", err)
	}
	if current.Type != cli.ContextTypeLocal || current.Local == nil {
		t.Fatalf("current context is %q (local=%v), want a local context", current.Type, current.Local)
	}
	return current.Local
}

func TestWriteLocalCLIConfigFailsForAMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")

	path, err := WriteLocalCLIConfig(dir, "/tmp/platformd-test.sock", "localhost:10443")
	if err == nil {
		t.Fatalf("WriteLocalCLIConfig into a missing directory returned %q and no error", path)
	}
	if path != "" {
		t.Errorf("path = %q on error, want empty", path)
	}
}

func TestWriteTempLocalCLIConfigWritesIntoItsOwnDirectory(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	dir, path, err := WriteTempLocalCLIConfig("/tmp/platformd-test.sock", "localhost:10443")
	if err != nil {
		t.Fatalf("WriteTempLocalCLIConfig: %v", err)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("config %q is not inside the returned directory %q", path, dir)
	}

	config, err := cli.LoadConfig(path)
	if err != nil {
		t.Fatalf("platformctl cannot load the written config: %v", err)
	}
	current, err := config.GetCurrentContext()
	if err != nil {
		t.Fatalf("resolve current context: %v", err)
	}
	if current.Local == nil || current.Local.SocketPath != "/tmp/platformd-test.sock" {
		t.Errorf("current context %+v does not dial the harness socket", current)
	}
}

func TestWriteTempLocalCLIConfigFailsWithoutATempDirectory(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))

	dir, path, err := WriteTempLocalCLIConfig("/tmp/platformd-test.sock", "localhost:10443")
	if err == nil {
		t.Fatalf("WriteTempLocalCLIConfig without a temp directory returned %q and no error", path)
	}
	if dir != "" || path != "" {
		t.Errorf("dir, path = %q, %q on error, want both empty", dir, path)
	}
	if _, statErr := os.Stat(os.Getenv("TMPDIR")); !os.IsNotExist(statErr) {
		t.Errorf("the failed call left something at TMPDIR: %v", statErr)
	}
}
