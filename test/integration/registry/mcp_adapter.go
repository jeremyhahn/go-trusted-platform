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

package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const (
	mcpProtocolVersion = "2024-11-05"
	mcpClientName      = "registry-integration-test"
	mcpClientVersion   = "1.0.0"
)

// The registry tools platformd serves (pkg/api/mcp/registry_tools.go).
const (
	mcpToolRegistryList    = "platform_registry_list"
	mcpToolRegistryInspect = "platform_registry_inspect"
	mcpToolRegistryDelete  = "platform_registry_delete"
	mcpToolRegistryStatus  = "platform_registry_status"
)

// ErrMCPRPC is a JSON-RPC error returned by the MCP server.
type ErrMCPRPC struct {
	Method  string
	Code    int
	Message string
}

func (e ErrMCPRPC) Error() string {
	return fmt.Sprintf("MCP %s error %d: %s", e.Method, e.Code, e.Message)
}

// MCPAdapter implements RegistryCommands over platformd's MCP JSON-RPC
// endpoint. List, Inspect, Delete and Status are the platform_registry_*
// tools; push and pull are not MCP tools (docs/registry/api.md §4), and the
// operations no transport serves return surface.ErrNoSurface.
type MCPAdapter struct {
	endpoint   string
	httpClient *http.Client
	requestID  atomic.Int64
}

// NewMCPAdapter creates a new MCP adapter for integration testing.
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup opens the MCP session with the initialize handshake.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformdMCPEndpoint)
	if endpoint == "" {
		endpoint = helpers.GetMCPEndpoint()
	}
	m.endpoint = helpers.MCPEndpointURL(endpoint)
	m.httpClient = helpers.NewHTTPClient(DefaultCommandTimeout)

	initParams := map[string]interface{}{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]interface{}{"name": mcpClientName, "version": mcpClientVersion},
	}
	var raw json.RawMessage
	if err := m.rpc(ctx, "initialize", initParams, &raw); err != nil {
		return ErrAdapterConnectionFailed{Adapter: "MCP", URL: m.endpoint, Err: err}
	}
	return nil
}

// Teardown releases idle connections.
func (m *MCPAdapter) Teardown() error {
	if m.httpClient != nil {
		m.httpClient.CloseIdleConnections()
	}
	return nil
}

type mcpRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type mcpRPCResponse struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// rpc sends one JSON-RPC request and decodes its result into out.
func (m *MCPAdapter) rpc(ctx context.Context, method string, params, out interface{}) error {
	body, err := json.Marshal(mcpRPCRequest{
		JSONRPC: "2.0",
		ID:      m.requestID.Add(1),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var envelope mcpRPCResponse
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return ErrInvalidResponse{Operation: method, Err: err}
	}
	if envelope.Error != nil {
		return ErrMCPRPC{Method: method, Code: envelope.Error.Code, Message: envelope.Error.Message}
	}
	if out != nil && len(envelope.Result) > 0 {
		return json.Unmarshal(envelope.Result, out)
	}
	return nil
}

// callTool invokes tools/call and decodes the tool's output into out.
// platformd answers with an MCP CallToolResult whose text block holds the
// tool's output as JSON, and a failed tool as a JSON-RPC error
// (pkg/api/mcp/server.go handleToolsCall).
func (m *MCPAdapter) callTool(ctx context.Context, tool string, args map[string]interface{}, out interface{}) error {
	var raw json.RawMessage
	if err := m.rpc(ctx, "tools/call", map[string]interface{}{"name": tool, "arguments": args}, &raw); err != nil {
		return err
	}
	var err error
	if out == nil {
		_, err = mcpwire.ToolOutputJSON(raw)
	} else {
		err = mcpwire.DecodeToolOutput(raw, out)
	}
	if err != nil {
		return ErrInvalidResponse{Operation: tool, Err: err}
	}
	return nil
}

// mcpArtifact is an artifact as pkg/api/daemon/mcp_registry.go renders it;
// times are UNIX milliseconds, 0 when unset.
type mcpArtifact struct {
	Repository  string            `json:"repository"`
	Tag         string            `json:"tag"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
	CreatedAt   int64             `json:"created_at"`
	UpdatedAt   int64             `json:"updated_at"`
}

// fromMilli converts the tools' millisecond timestamps, keeping 0 as unset.
func fromMilli(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

func (a mcpArtifact) manifest() ImageManifest {
	return ImageManifest{
		Reference:   a.Repository + ":" + a.Tag,
		Digest:      a.Digest,
		Size:        a.Size,
		Annotations: a.Annotations,
		CreatedAt:   fromMilli(a.CreatedAt),
		UpdatedAt:   fromMilli(a.UpdatedAt),
	}
}

// Push is not an MCP tool.
func (m *MCPAdapter) Push(ctx context.Context, ref string, opts PushOptions) (*PushResult, error) {
	return nil, noSurface(m.Name(), opPush)
}

// Pull is not an MCP tool.
func (m *MCPAdapter) Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	return nil, noSurface(m.Name(), opPull)
}

// List calls platform_registry_list.
func (m *MCPAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	args := map[string]interface{}{
		"repository": opts.Repository,
		"limit":      opts.Limit,
		"cursor":     opts.Cursor,
		"sort_by":    opts.SortBy,
		"ascending":  !opts.SortDesc,
	}
	var resp struct {
		Total      int           `json:"total"`
		HasMore    bool          `json:"has_more"`
		NextCursor string        `json:"next_cursor"`
		Artifacts  []mcpArtifact `json:"artifacts"`
	}
	if err := m.callTool(ctx, mcpToolRegistryList, args, &resp); err != nil {
		return nil, err
	}
	result := &ListResult{TotalCount: resp.Total, HasMore: resp.HasMore, NextCursor: resp.NextCursor}
	for _, a := range resp.Artifacts {
		result.Images = append(result.Images, a.manifest())
	}
	return result, nil
}

// Delete calls platform_registry_delete.
func (m *MCPAdapter) Delete(ctx context.Context, ref string, opts DeleteOptions) (*DeleteResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}
	repository, tag := splitImageRef(ref)
	args := map[string]interface{}{"repository": repository, "reference": tag, "force": opts.Force}
	var resp struct {
		Digest    string `json:"digest"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := m.callTool(ctx, mcpToolRegistryDelete, args, &resp); err != nil {
		return nil, err
	}
	return &DeleteResult{Reference: ref, Digest: resp.Digest, DeletedAt: fromMilli(resp.Timestamp)}, nil
}

// Inspect calls platform_registry_inspect.
func (m *MCPAdapter) Inspect(ctx context.Context, ref string) (*InspectResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}
	repository, tag := splitImageRef(ref)
	args := map[string]interface{}{"repository": repository, "reference": tag}
	var resp struct {
		Artifact mcpArtifact `json:"artifact"`
	}
	if err := m.callTool(ctx, mcpToolRegistryInspect, args, &resp); err != nil {
		return nil, err
	}
	manifest := resp.Artifact.manifest()
	manifest.Reference = ref
	return &InspectResult{Reference: ref, Manifest: &manifest, TotalSize: resp.Artifact.Size}, nil
}

// Status calls platform_registry_status.
func (m *MCPAdapter) Status(ctx context.Context) (*StatusResult, error) {
	var resp struct {
		Health    string `json:"health"`
		Version   string `json:"version"`
		StartedAt int64  `json:"started_at"`
		Timestamp int64  `json:"timestamp"`
		Storage   struct {
			UsedBytes     int64 `json:"used_bytes"`
			ArtifactCount int   `json:"artifact_count"`
		} `json:"storage"`
	}
	if err := m.callTool(ctx, mcpToolRegistryStatus, map[string]interface{}{}, &resp); err != nil {
		return nil, err
	}
	healthy := resp.Health == "healthy"
	result := &StatusResult{
		Healthy:    healthy,
		Status:     "degraded",
		Version:    resp.Version,
		ImageCount: resp.Storage.ArtifactCount,
		TotalSize:  resp.Storage.UsedBytes,
	}
	if healthy {
		result.Status = "running"
	}
	if resp.StartedAt != 0 && resp.Timestamp != 0 {
		result.Uptime = fromMilli(resp.Timestamp).Sub(fromMilli(resp.StartedAt))
	}
	return result, nil
}

// Tag is served by no transport.
func (m *MCPAdapter) Tag(ctx context.Context, sourceRef, targetRef string) (*TagResult, error) {
	return nil, noSurface(m.Name(), opTag)
}

// VerifyClient is served by no transport.
func (m *MCPAdapter) VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error) {
	return nil, noSurface(m.Name(), opVerifyClient)
}

// GetSession is served by no transport.
func (m *MCPAdapter) GetSession(ctx context.Context, clientID string) (*SessionResult, error) {
	return nil, noSurface(m.Name(), opGetSession)
}

// InvalidateSession is served by no transport.
func (m *MCPAdapter) InvalidateSession(ctx context.Context, clientID string) error {
	return noSurface(m.Name(), opInvalidateSession)
}

// EncryptImage is served by no transport.
func (m *MCPAdapter) EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error) {
	return nil, noSurface(m.Name(), opEncryptImage)
}

// DecryptImage is served by no transport.
func (m *MCPAdapter) DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error) {
	return nil, noSurface(m.Name(), opDecryptImage)
}
