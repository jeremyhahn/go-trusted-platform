//go:build integration

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

package sdn

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// quicOpNAT64Status is the gateway-category sub-opcode of GetNAT64Status.
const quicOpNAT64Status byte = 0x39

// TestNAT64StatusMultiProtocol proves the NAT64 status verb (#601 PR 2) is
// served on every transport against the integration platformd.
//
// That platformd runs no gateway translator: the NAT64 service is
// gatewayd-resident, and the control-plane wiring that would reach it is
// #660, which waits on an owner ruling. So every transport must answer with
// its "not configured" mapping: gRPC Unavailable, REST 503, QUIC
// Unavailable, a CLI error naming the translator. MCP is covered in its own
// case. None may answer with "unknown method", 404, an unmapped opcode or
// an unclassified tool. Those would mean the verb is not routed on that
// transport, which is the defect class #661 fixed in the SDK adapters. The translator itself is proven end to end by
// `make integration-test-nat64`.
func TestNAT64StatusMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("CLI", func(t *testing.T) {
		cli := NewCLIAdapter()
		require.NoError(t, cli.Setup(ctx))
		t.Cleanup(func() { _ = cli.Teardown() })
		_, err := cli.runCommand(ctx, "sdn", "gateway", "nat64", "status")
		require.Error(t, err, "no translator is configured on the integration platformd")
		require.Contains(t, strings.ToLower(err.Error()), "nat64 translator not configured")
	})

	grpcCase := func(name, target string, opts ...grpc.DialOption) {
		t.Run(name, func(t *testing.T) {
			conn, err := grpc.NewClient(target, opts...)
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			_, err = platformv1.NewGatewayServiceClient(conn).GetNAT64Status(ctx, &platformv1.GetNAT64StatusRequest{})
			require.Equal(t, codes.Unavailable, status.Code(err), "got %v", err)
			require.Contains(t, status.Convert(err).Message(), "nat64 translator not configured")
		})
	}
	endpoints := GetServiceEndpoints()
	grpcCase("gRPC", endpoints.PlatformdGRPC, helpers.GRPCTransportCredentials())
	grpcCase("Unix", "unix://"+endpoints.PlatformdSock, helpers.GRPCUnixCredentials())

	t.Run("REST", func(t *testing.T) {
		client := helpers.NewHTTPClient(30 * time.Second)
		t.Cleanup(client.CloseIdleConnections)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, NewSDNRESTAdapter().baseURL+"/api/v1/sdn/gateway/nat64/status", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "the route exists and reports the translator absent: %s", body)
	})

	t.Run("QUIC", func(t *testing.T) {
		q := NewSDNQUICAdapter()
		require.NoError(t, q.Setup(ctx))
		t.Cleanup(func() { _ = q.Teardown() })
		_, err := q.sendCategoryRequest(ctx, opGatewayCategory, quicOpNAT64Status, nil)
		var unavailable ErrQUICSDNUnavailable
		require.ErrorAs(t, err, &unavailable, "the sub-opcode is dispatched and reports the translator absent")
		require.Contains(t, err.Error(), "not configured")
	})

	t.Run("MCP", func(t *testing.T) {
		m := NewSDNMCPAdapter()
		require.NoError(t, m.Setup(ctx))
		t.Cleanup(func() { _ = m.Teardown() })
		_, err := m.callTool(ctx, "gateway_nat64_status", map[string]interface{}{})
		require.Error(t, err)
		// The tool must be registered and carry a permission mapping. An
		// unregistered or unmapped tool is refused with "has no permission
		// mapping" before anything else is checked (#300). Past that check,
		// AuthorizeTool (pkg/api/mcp/authz.go) refuses a call that carries no
		// token with "Authentication required for this operation" -- with or
		// without an authorization backend; without one the message goes on
		// to name the missing backend (#440). This suite's platformd runs
		// the production QuicBaaS backend and the adapter holds no token
		// (#730), so that refusal is today's answer; a caller with a token
		// reaches the provider, which reports the translator absent. Either
		// answer is only reachable once the verb is routed and classified.
		require.NotContains(t, err.Error(), "no permission mapping")
		msg := err.Error()
		require.True(t,
			strings.Contains(msg, "service not available: nat64") ||
				strings.Contains(msg, "Authentication required for this operation"),
			"gateway_nat64_status must be routed and classified: %v", err)
	})
}
