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

// tls_identity_fail_closed_test.go asserts the fail-closed contract of
// applyDaemonTLSIdentity (#32): when a TLS-terminating transport is enabled
// and the daemon identity cannot be provisioned, the function returns a typed
// error and serve aborts startup instead of warning and serving plaintext.

package commands

import (
	"context"
	"errors"
	"testing"

	daemon "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
)

// tlsTransportConfig returns a daemon config with one TLS-terminating
// transport enabled, which obliges applyDaemonTLSIdentity to produce an
// identity or fail.
func tlsTransportConfig() *daemon.Config {
	cfg := daemon.DefaultConfig()
	cfg.EnableREST = false
	cfg.EnableQUIC = false
	cfg.EnableGRPCTCP = true
	return cfg
}

func TestApplyDaemonTLSIdentity_NilAppFailsClosed(t *testing.T) {
	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), nil, tlsTransportConfig(), false)
	if err == nil {
		t.Fatal("expected typed error for nil app, got nil")
	}
	var typed ErrTLSIdentityRequiresApp
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrTLSIdentityRequiresApp, got %T (%v)", err, err)
	}
}

func TestApplyDaemonTLSIdentity_NilCAFailsClosed(t *testing.T) {
	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{}, tlsTransportConfig(), false)
	if err == nil {
		t.Fatal("expected typed error for nil CA, got nil")
	}
	var typed ErrProvisionMissingCA
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionMissingCA, got %T (%v)", err, err)
	}
}

func TestApplyDaemonTLSIdentity_NilConfigFailsClosed(t *testing.T) {
	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{}, nil, false)
	if err == nil {
		t.Fatal("expected typed error for nil config, got nil")
	}
	var typed ErrTLSIdentityRequiresConfig
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrTLSIdentityRequiresConfig, got %T (%v)", err, err)
	}
}

// TestApplyDaemonTLSIdentity_MCPHTTPOnlyRequiresIdentity asserts the MCP
// HTTP transport counts as TLS-terminating (#844): with every other network
// transport off it still needs the daemon identity, so a missing CA fails
// closed instead of being skipped as UDS-only mode.
func TestApplyDaemonTLSIdentity_MCPHTTPOnlyRequiresIdentity(t *testing.T) {
	cfg := daemon.DefaultConfig()
	cfg.EnableREST = false
	cfg.EnableGRPCTCP = false
	cfg.EnableQUIC = false
	cfg.EnableMCP = true
	cfg.MCPConfig = daemon.DefaultMCPConfig()
	cfg.MCPConfig.Transport = "http"

	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{}, cfg, false)
	var typed ErrProvisionMissingCA
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionMissingCA for MCP-HTTP-only mode, got %T (%v)", err, err)
	}
}

// TestApplyDaemonTLSIdentity_MCPStdioOnlySkips asserts stdio MCP binds no
// network listener and so, like UDS, needs no TLS identity.
func TestApplyDaemonTLSIdentity_MCPStdioOnlySkips(t *testing.T) {
	cfg := daemon.DefaultConfig()
	cfg.EnableREST = false
	cfg.EnableGRPCTCP = false
	cfg.EnableQUIC = false
	cfg.EnableMCP = true
	cfg.MCPConfig = daemon.DefaultMCPConfig()
	cfg.MCPConfig.Transport = "stdio"

	if err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{}, cfg, false); err != nil {
		t.Fatalf("stdio MCP must not require a TLS identity, got %v", err)
	}
}

// TestApplyDaemonTLSIdentity_UDSOnlySkips asserts the sanctioned carve-out:
// with no TLS-terminating transport enabled (Unix-domain-socket-only mode)
// the daemon needs no TLS identity and startup proceeds.
func TestApplyDaemonTLSIdentity_UDSOnlySkips(t *testing.T) {
	cfg := daemon.DefaultConfig()
	cfg.EnableREST = false
	cfg.EnableGRPCTCP = false
	cfg.EnableQUIC = false
	cfg.EnableGRPCUDS = true

	// Even with a nil CA the UDS-only daemon must start: the carve-out is
	// decided before any provisioning dependency is touched.
	if err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{}, cfg, false); err != nil {
		t.Fatalf("UDS-only mode must not require a TLS identity, got %v", err)
	}
	if cfg.TLSCertificate != nil {
		t.Error("UDS-only mode must not install TLS material")
	}
}
