// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict/feed"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func mcpTokenCtx(tenantID string, scopes ...string) context.Context {
	return mcp.ContextWithAuthorizedContext(context.Background(),
		&platformtoken.AuthorizedContext{Subject: "s", TenantID: tenantID, Scopes: scopes})
}

// pollVerdictsOverMCP calls attestation_device_verdicts_poll through the MCP
// tool registry, as an MCP client does.
func pollVerdictsOverMCP(ctx context.Context, p *MCPServiceProvider, args map[string]interface{}) (map[string]interface{}, error) {
	out, err := mcp.NewToolRegistry(p, logging.DefaultLogger()).ExecuteTool(ctx, "attestation_device_verdicts_poll", args)
	if err != nil {
		return nil, err
	}
	return out.(map[string]interface{}), nil
}

// TestMCPPollDeviceVerdicts follows verdicts over MCP: the token's tenant
// filters what it sees, and the verdict reaches the client in the proto's
// JSON names, which the SDK decodes with protojson.
func TestMCPPollDeviceVerdicts(t *testing.T) {
	server, attestation, _, _ := verdictFeedServer(t)
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{AttestationServer: server})
	ctx := mcpTokenCtx("tenant-a", "attestation:read")

	head, err := pollVerdictsOverMCP(ctx, p, map[string]interface{}{})
	if err != nil || head["cursor"] == "" {
		t.Fatalf("the first poll returns the head cursor: %v, %v", head, err)
	}
	attestation.record(verdict.DeviceVerdict{DeviceID: 1, TenantID: "tenant-b"}, "ev-b")
	attestation.record(verdict.DeviceVerdict{DeviceID: 2, TenantID: "tenant-a", HostID: "node-2", Reason: "signature invalid"}, "ev-a")

	page, err := pollVerdictsOverMCP(ctx, p, map[string]interface{}{"cursor": head["cursor"], "wait_ms": float64(1000)})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	verdicts, _ := page["verdicts"].([]interface{})
	if len(verdicts) != 1 {
		t.Fatalf("tenant-a must see only its own device's verdict: %+v", page)
	}
	got := verdicts[0].(map[string]interface{})
	if got["event_id"] != "ev-a" || got["device_id"] != "2" || got["host_id"] != "node-2" ||
		got["reason"] != "signature invalid" || got["recorded_at"] != "2026-10-09T12:00:00Z" {
		t.Fatalf("verdict = %+v", got)
	}
}

func TestMCPPollDeviceVerdictsRefusals(t *testing.T) {
	server, attestation, _, _ := verdictFeedServer(t, feed.WithCapacity(1))
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{AttestationServer: server})
	reader := mcpTokenCtx("tenant-a", "attestation:read")

	head, err := pollVerdictsOverMCP(reader, p, map[string]interface{}{})
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	attestation.record(verdict.DeviceVerdict{DeviceID: 1, TenantID: "tenant-a"}, "ev-1")
	attestation.record(verdict.DeviceVerdict{DeviceID: 2, TenantID: "tenant-a"}, "ev-2")

	tests := []struct {
		name string
		ctx  context.Context
		args map[string]interface{}
		want codes.Code
	}{
		{name: "no token", ctx: context.Background(), args: map[string]interface{}{}, want: codes.PermissionDenied},
		{name: "token without the scope", ctx: mcpTokenCtx("tenant-a", "device:read"), args: map[string]interface{}{}, want: codes.PermissionDenied},
		{name: "token without a tenant", ctx: mcpTokenCtx("", "attestation:read"), args: map[string]interface{}{}, want: codes.PermissionDenied},
		{name: "missed verdicts", ctx: reader, args: map[string]interface{}{"cursor": head["cursor"]}, want: codes.ResourceExhausted},
		{name: "malformed cursor", ctx: reader, args: map[string]interface{}{"cursor": "garbage"}, want: codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := pollVerdictsOverMCP(tt.ctx, p, tt.args); status.Code(err) != tt.want {
				t.Fatalf("err = %v, want %s", err, tt.want)
			}
		})
	}

	t.Run("no attestation service", func(t *testing.T) {
		bare := NewMCPServiceProvider(&MCPServiceProviderConfig{})
		if _, err := pollVerdictsOverMCP(reader, bare, map[string]interface{}{}); !errors.Is(err, mcp.ErrDeviceVerdictsNotConfigured) {
			t.Fatalf("err = %v, want ErrDeviceVerdictsNotConfigured", err)
		}
	})
}
