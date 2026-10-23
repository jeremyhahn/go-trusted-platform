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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newDEKMCP builds the MCP tool registry over a DEK adapter backed by client.
func newDEKMCP(client *fakeDEKClient) *mcp.ToolRegistry {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DEKService: NewDEKServerAdapter(client, slog.Default()),
		Logger:     slog.Default(),
	})
	return mcp.NewToolRegistry(provider, logging.DefaultLogger())
}

// clearResponseTimestamp clears the response's timestamp field, which the
// adapter stamps from the wall clock on each call.
func clearResponseTimestamp(m proto.Message) {
	msg := m.ProtoReflect()
	if fd := msg.Descriptor().Fields().ByName("timestamp"); fd != nil {
		msg.Clear(fd)
	}
}

// TestMCPDEKProvider checks each dek_* tool reaches the DEK client with the
// caller's arguments and answers the DEKManagement response.
func TestMCPDEKProvider(t *testing.T) {
	client := &fakeDEKClient{info: testDEKInfo()}
	tools := newDEKMCP(client)

	t.Run("Create", func(t *testing.T) {
		var out pb.CreateDEKResponse
		require.NoError(t, parityTool(t, tools, "dek_create", map[string]interface{}{
			"path":           "tenants/a/dek",
			"description":    "orders",
			"max_operations": float64(100),
		}, &out))
		assert.Equal(t, uint64(3), out.GetDek().GetVersion())
		assert.Equal(t, "tenants/a/dek", client.lastCreate.Path)
		assert.Equal(t, uint64(100), client.lastCreate.MaxOperations)
		assert.Equal(t, "orders", client.lastCreate.Description)
	})

	t.Run("List", func(t *testing.T) {
		var out pb.ListDEKsResponse
		require.NoError(t, parityTool(t, tools, "dek_list", map[string]interface{}{
			"prefix": "tenants/", "recursive": true,
		}, &out))
		require.Len(t, out.GetDeks(), 1)
		assert.Equal(t, "tenants/a/dek", out.GetDeks()[0].GetPath())
		assert.Equal(t, "tenants/", client.lastList.Prefix)
		assert.True(t, client.lastList.Recursive)
	})

	t.Run("Get", func(t *testing.T) {
		var out pb.GetDEKResponse
		require.NoError(t, parityTool(t, tools, "dek_get", map[string]interface{}{"path": "tenants/a/dek"}, &out))
		assert.Equal(t, "tenants/a/dek", out.GetDek().GetPath())
		assert.Equal(t, "tenants/a/dek", client.lastPath)
	})

	t.Run("Status", func(t *testing.T) {
		var out pb.GetDEKStatusResponse
		require.NoError(t, parityTool(t, tools, "dek_status", map[string]interface{}{"path": "tenants/a/dek"}, &out))
		assert.InDelta(t, 50.0, out.GetUsagePercent(), 0.001)
	})

	t.Run("Rotate", func(t *testing.T) {
		var out pb.RotateDEKResponse
		require.NoError(t, parityTool(t, tools, "dek_rotate", map[string]interface{}{
			"path": "tenants/a/dek", "background": true,
		}, &out))
		assert.Equal(t, uint64(2), out.GetNewVersion())
		assert.Equal(t, "tenants/a/dek", client.lastRotate.Path)
	})

	t.Run("Delete", func(t *testing.T) {
		var out pb.DeleteDEKResponse
		require.NoError(t, parityTool(t, tools, "dek_delete", map[string]interface{}{
			"path": "tenants/a/dek", "force": true,
		}, &out))
		assert.True(t, out.GetDeleted())
		assert.Equal(t, "tenants/a/dek", client.lastDelete.Path)
		assert.True(t, client.lastDelete.Force)
	})
}

// TestMCPDEKProviderErrors checks the provider refuses without a DEK service
// or a request and carries the adapter's error class.
func TestMCPDEKProviderErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("no DEK service", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{Logger: slog.Default()})
		_, err := provider.DEKGet(ctx, "tenants/a/dek")
		assert.ErrorIs(t, err, ErrServiceNotAvailable{Service: "dek"})
		assert.Equal(t, codes.Unavailable, mcpErrorClass(err))
	})

	t.Run("nil request", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
			DEKService: NewDEKServerAdapter(&fakeDEKClient{info: testDEKInfo()}, slog.Default()),
			Logger:     slog.Default(),
		})
		_, err := provider.DEKCreate(ctx, nil)
		assert.Equal(t, codes.InvalidArgument, mcpErrorClass(err), "create: %v", err)
		_, err = provider.DEKDelete(ctx, nil)
		assert.Equal(t, codes.InvalidArgument, mcpErrorClass(err), "delete: %v", err)
		_, err = provider.DEKList(ctx, nil)
		assert.NoError(t, err, "list takes a nil request as the whole store")
	})

	failing := newDEKMCP(&fakeDEKClient{err: errKMSLifecycleMock{method: "DEK"}})
	classes := map[string]codes.Code{
		"dek_create": codes.Internal,
		"dek_get":    codes.NotFound,
		"dek_status": codes.NotFound,
		"dek_rotate": codes.Internal,
		"dek_delete": codes.Internal,
	}
	for tool, want := range classes {
		t.Run(tool+" failure", func(t *testing.T) {
			var out map[string]interface{}
			err := parityTool(t, failing, tool, map[string]interface{}{"path": "tenants/a/dek"}, &out)
			var opErr ErrDEKOperationFailed
			require.ErrorAs(t, err, &opErr)
			assert.Equal(t, want, mcpErrorClass(err), "%v", err)
		})
	}
}

// TestMCPKMSParity_DEK checks each dek_* tool answers what the gRPC
// DEKManagement RPC answers, and fails with the same class.
func TestMCPKMSParity_DEK(t *testing.T) {
	ctx := context.Background()
	tools := newDEKMCP(&fakeDEKClient{info: testDEKInfo()})
	adapter := NewDEKServerAdapter(&fakeDEKClient{info: testDEKInfo()}, slog.Default())

	cases := []struct {
		tool string
		args map[string]interface{}
		mcp  proto.Message
		grpc func() (proto.Message, error)
	}{
		{"dek_create", map[string]interface{}{"path": "tenants/a/dek"}, &pb.CreateDEKResponse{},
			func() (proto.Message, error) {
				return adapter.CreateDEK(ctx, &pb.CreateDEKRequest{Path: "tenants/a/dek"})
			}},
		{"dek_list", map[string]interface{}{"prefix": "tenants/"}, &pb.ListDEKsResponse{},
			func() (proto.Message, error) {
				return adapter.ListDEKs(ctx, &pb.ListDEKsRequest{Prefix: "tenants/"})
			}},
		{"dek_get", map[string]interface{}{"path": "tenants/a/dek"}, &pb.GetDEKResponse{},
			func() (proto.Message, error) {
				return adapter.GetDEK(ctx, &pb.GetDEKRequest{Path: "tenants/a/dek"})
			}},
		{"dek_status", map[string]interface{}{"path": "tenants/a/dek"}, &pb.GetDEKStatusResponse{},
			func() (proto.Message, error) {
				return adapter.GetDEKStatus(ctx, &pb.GetDEKStatusRequest{Path: "tenants/a/dek"})
			}},
		{"dek_rotate", map[string]interface{}{"path": "tenants/a/dek"}, &pb.RotateDEKResponse{},
			func() (proto.Message, error) {
				return adapter.RotateDEK(ctx, &pb.RotateDEKRequest{Path: "tenants/a/dek"})
			}},
		{"dek_delete", map[string]interface{}{"path": "tenants/a/dek"}, &pb.DeleteDEKResponse{},
			func() (proto.Message, error) {
				return adapter.DeleteDEK(ctx, &pb.DeleteDEKRequest{Path: "tenants/a/dek"})
			}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			require.NoError(t, parityTool(t, tools, tc.tool, tc.args, tc.mcp))
			want, err := tc.grpc()
			require.NoError(t, err)
			clearResponseTimestamp(want)
			clearResponseTimestamp(tc.mcp)
			assert.True(t, proto.Equal(want, tc.mcp), "MCP %v\ngRPC %v", tc.mcp, want)
		})
	}

	t.Run("missing path", func(t *testing.T) {
		var out map[string]interface{}
		mcpErr := parityTool(t, tools, "dek_get", map[string]interface{}{}, &out)
		_, grpcErr := adapter.GetDEK(ctx, &pb.GetDEKRequest{})
		requireSameClass(t, mcpErr, grpcErr, codes.InvalidArgument)
	})

	t.Run("backend failure", func(t *testing.T) {
		failingTools := newDEKMCP(&fakeDEKClient{err: errKMSLifecycleMock{method: "GetDEK"}})
		failingAdapter := NewDEKServerAdapter(&fakeDEKClient{err: errKMSLifecycleMock{method: "GetDEK"}}, slog.Default())
		var out map[string]interface{}
		mcpErr := parityTool(t, failingTools, "dek_get", map[string]interface{}{"path": "tenants/a/dek"}, &out)
		_, grpcErr := failingAdapter.GetDEK(ctx, &pb.GetDEKRequest{Path: "tenants/a/dek"})
		requireSameClass(t, mcpErr, grpcErr, codes.NotFound)
	})
}
