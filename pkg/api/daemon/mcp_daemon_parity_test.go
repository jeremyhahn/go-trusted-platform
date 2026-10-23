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

package daemon

import (
	"context"
	"log/slog"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newDaemonParityFixture returns the PlatformDaemon gRPC service with a tpm
// service registered, and an MCP provider reading the same service.
func newDaemonParityFixture(t *testing.T) (*Service, *MCPServiceProvider) {
	t.Helper()
	svc, err := NewService(DefaultConfig())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.RegisterService(newMockService("tpm")); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		HealthService: svc,
		Logger:        slog.Default(),
	})
	return svc, provider
}

// TestDaemonMCPGetServiceMatchesGRPC asserts platform_daemon_get_service
// returns what gRPC GetServiceStatus returns for a registered service, and
// the same NotFound class for an unregistered one.
func TestDaemonMCPGetServiceMatchesGRPC(t *testing.T) {
	ctx := context.Background()
	svc, provider := newDaemonParityFixture(t)

	grpcResp, err := svc.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{Service: platformv1.ServiceType_SERVICE_TYPE_TPM})
	if err != nil {
		t.Fatalf("gRPC GetServiceStatus: %v", err)
	}
	mcpResp, err := provider.DaemonGetService(ctx, "tpm")
	if err != nil {
		t.Fatalf("MCP DaemonGetService: %v", err)
	}
	info, ok := mcpResp.(map[string]interface{})
	if !ok {
		t.Fatalf("MCP result type = %T, want map", mcpResp)
	}
	if info["name"] != grpcResp.GetService().GetName() {
		t.Fatalf("MCP name = %v, gRPC name = %s", info["name"], grpcResp.GetService().GetName())
	}
	if info["status"] != mcpServiceStatusString(grpcResp.GetService().GetStatus()) {
		t.Fatalf("MCP status = %v, gRPC status = %v", info["status"], grpcResp.GetService().GetStatus())
	}

	_, grpcErr := svc.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{Service: platformv1.ServiceType_SERVICE_TYPE_DNS})
	_, mcpErr := provider.DaemonGetService(ctx, "dns")
	if got := status.Code(grpcErr); got != codes.NotFound {
		t.Fatalf("gRPC code = %v, want NotFound", got)
	}
	if got := status.Code(mcpErr); got != codes.NotFound {
		t.Fatalf("MCP code = %v, want NotFound (err: %v)", got, mcpErr)
	}
}

// TestDaemonMCPVersionMatchesGRPC asserts platform_daemon_version returns the
// version gRPC GetVersion returns.
func TestDaemonMCPVersionMatchesGRPC(t *testing.T) {
	ctx := context.Background()
	svc, provider := newDaemonParityFixture(t)

	grpcResp, err := svc.GetVersion(ctx, &platformv1.GetVersionRequest{})
	if err != nil {
		t.Fatalf("gRPC GetVersion: %v", err)
	}
	mcpResp, err := provider.DaemonVersion(ctx)
	if err != nil {
		t.Fatalf("MCP DaemonVersion: %v", err)
	}
	version, ok := mcpResp.(map[string]interface{})
	if !ok {
		t.Fatalf("MCP result type = %T, want map", mcpResp)
	}
	if version["version"] != grpcResp.GetVersion() || version["goVersion"] != grpcResp.GetGoVersion() {
		t.Fatalf("MCP version = %v, gRPC = %s/%s", version, grpcResp.GetVersion(), grpcResp.GetGoVersion())
	}
}

// TestDaemonMCPUnwiredServiceIsUnavailable asserts the MCP daemon reads
// answer Unavailable, not Internal, when no daemon service is wired.
func TestDaemonMCPUnwiredServiceIsUnavailable(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{Logger: slog.Default()})

	_, err := provider.DaemonGetService(context.Background(), "tpm")
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable (err: %v)", got, err)
	}
}
