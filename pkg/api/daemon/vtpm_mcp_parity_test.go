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
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newVTPMStore is an in-memory vTPM service holding bundle b1 and template
// t1. Unknown ids fail with the vtpm package's typed not-found errors.
func newVTPMStore() *mockVTPMService {
	bundles := map[string]*vtpm.Bundle{"b1": {ID: "b1"}}
	templates := map[string]*vtpm.Template{"t1": {ID: "t1"}}
	return &mockVTPMService{
		getBundleFunc: func(_ context.Context, id string) (*vtpm.Bundle, error) {
			if b, ok := bundles[id]; ok {
				return b, nil
			}
			return nil, vtpm.ErrBundleNotFound{ID: id}
		},
		validateBundleFunc: func(_ context.Context, id string) error {
			if _, ok := bundles[id]; ok {
				return nil
			}
			return vtpm.ErrBundleNotFound{ID: id}
		},
		getTemplateFunc: func(_ context.Context, id string) (*vtpm.Template, error) {
			if t, ok := templates[id]; ok {
				return t, nil
			}
			return nil, vtpm.ErrTemplateNotFound{ID: id}
		},
		deleteTemplateFunc: func(_ context.Context, id string) error {
			if _, ok := templates[id]; !ok {
				return vtpm.ErrTemplateNotFound{ID: id}
			}
			delete(templates, id)
			return nil
		},
		getBundlePathFunc: func(id string) string { return "/bundles/" + id },
		isRunningFunc:     func(string) bool { return true },
	}
}

func newVTPMParityPair() (*VTPMServiceServer, *MCPServiceProvider) {
	store := newVTPMStore()
	return NewVTPMServiceServer(store, slog.New(slog.DiscardHandler)), newMCPProviderWithVTPM(store)
}

// TestVTPMParity_Bundle: vtpm_get gives gRPC GetBundle's bundle, NotFound for
// an unknown id and InvalidArgument for none. MCP used to return the raw
// error, which the MCP server classed as InternalError.
func TestVTPMParity_Bundle(t *testing.T) {
	ctx := context.Background()
	grpcSvc, mcp := newVTPMParityPair()

	resp, err := grpcSvc.GetBundle(ctx, &platformv1.GetBundleRequest{Id: "b1"})
	require.NoError(t, err)
	got, err := mcp.VTPMGet(ctx, "b1")
	require.NoError(t, err)
	assert.Equal(t, resp.GetBundle().GetId(), got.(*vtpm.Bundle).ID)

	_, grpcErr := grpcSvc.GetBundle(ctx, &platformv1.GetBundleRequest{Id: "absent"})
	_, mcpErr := mcp.VTPMGet(ctx, "absent")
	assert.Equal(t, codes.NotFound, status.Code(grpcErr))
	assert.Equal(t, codes.NotFound, status.Code(mcpErr))

	_, grpcErr = grpcSvc.GetBundle(ctx, &platformv1.GetBundleRequest{})
	_, mcpErr = mcp.VTPMGet(ctx, "")
	assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr))
	assert.Equal(t, codes.InvalidArgument, status.Code(mcpErr))
}

// TestVTPMParity_Validate: an absent bundle is valid=false on both
// transports. MCP used to fail the call instead.
func TestVTPMParity_Validate(t *testing.T) {
	ctx := context.Background()
	grpcSvc, mcp := newVTPMParityPair()

	for _, id := range []string{"b1", "absent"} {
		resp, err := grpcSvc.ValidateBundle(ctx, &platformv1.ValidateBundleRequest{Id: id})
		require.NoError(t, err)
		got, err := mcp.VTPMValidate(ctx, id)
		require.NoError(t, err, id)
		assert.Equal(t, resp.GetValid(), got.(map[string]interface{})["valid"], id)
	}

	_, grpcErr := grpcSvc.ValidateBundle(ctx, &platformv1.ValidateBundleRequest{})
	_, mcpErr := mcp.VTPMValidate(ctx, "")
	assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr))
	assert.Equal(t, codes.InvalidArgument, status.Code(mcpErr))
}

// TestVTPMParity_Template: get and delete answer as gRPC does for a known,
// an unknown and an empty template id.
func TestVTPMParity_Template(t *testing.T) {
	ctx := context.Background()
	grpcSvc, mcp := newVTPMParityPair()

	resp, err := grpcSvc.GetTemplate(ctx, &platformv1.GetTemplateRequest{Id: "t1"})
	require.NoError(t, err)
	got, err := mcp.VTPMGetTemplate(ctx, "t1")
	require.NoError(t, err)
	assert.Equal(t, resp.GetTemplate().GetId(), got.(*vtpm.Template).ID)

	_, grpcErr := grpcSvc.GetTemplate(ctx, &platformv1.GetTemplateRequest{Id: "absent"})
	_, mcpErr := mcp.VTPMGetTemplate(ctx, "absent")
	assert.Equal(t, codes.NotFound, status.Code(grpcErr))
	assert.Equal(t, codes.NotFound, status.Code(mcpErr))

	_, grpcErr = grpcSvc.DeleteTemplate(ctx, &platformv1.DeleteTemplateRequest{Id: "absent"})
	mcpErr = mcp.VTPMDeleteTemplate(ctx, "absent")
	assert.Equal(t, codes.NotFound, status.Code(grpcErr))
	assert.Equal(t, codes.NotFound, status.Code(mcpErr))

	_, grpcErr = grpcSvc.DeleteTemplate(ctx, &platformv1.DeleteTemplateRequest{})
	mcpErr = mcp.VTPMDeleteTemplate(ctx, "")
	assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr))
	assert.Equal(t, codes.InvalidArgument, status.Code(mcpErr))

	require.NoError(t, mcp.VTPMDeleteTemplate(ctx, "t1"))
	_, grpcErr = grpcSvc.GetTemplate(ctx, &platformv1.GetTemplateRequest{Id: "t1"})
	assert.Equal(t, codes.NotFound, status.Code(grpcErr), "MCP delete did not delete")
}

// TestVTPMParity_Paths: the path and is-running lookups give gRPC's answer
// and refuse an empty bundle id as gRPC does.
func TestVTPMParity_Paths(t *testing.T) {
	ctx := context.Background()
	grpcSvc, mcp := newVTPMParityPair()

	resp, err := grpcSvc.GetBundlePath(ctx, &platformv1.GetBundlePathRequest{Id: "b1"})
	require.NoError(t, err)
	got, err := mcp.VTPMGetBundlePath(ctx, "b1")
	require.NoError(t, err)
	assert.Equal(t, resp.GetPath(), got.(map[string]interface{})["path"])

	empty := map[string]func() error{
		"bundle path": func() error { _, err := mcp.VTPMGetBundlePath(ctx, ""); return err },
		"socket path": func() error { _, err := mcp.VTPMGetTPMSocketPath(ctx, ""); return err },
		"nvram path":  func() error { _, err := mcp.VTPMGetNVRAMPath(ctx, ""); return err },
		"is running":  func() error { _, err := mcp.VTPMIsRunning(ctx, ""); return err },
		"export":      func() error { _, err := mcp.VTPMExport(ctx, ""); return err },
	}
	_, grpcErr := grpcSvc.GetBundlePath(ctx, &platformv1.GetBundlePathRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(grpcErr))
	for name, call := range empty {
		assert.Equal(t, codes.InvalidArgument, status.Code(call()), name)
	}
}
