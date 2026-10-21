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

package vtpm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// MCP Constants
// =============================================================================

const (
	// DefaultMCPTimeoutVTPM is the default timeout for MCP operations.
	// Kept at 10s per project convention to avoid slow test skips when the
	// MCP server is unavailable.
	DefaultMCPTimeoutVTPM = 10 * time.Second

	// mcpVTPMProtocolVersion is the MCP protocol version.
	mcpVTPMProtocolVersion = "2024-11-05"

	// mcpVTPMClientName is the name of this MCP test client.
	mcpVTPMClientName = "vtpm-integration-test"

	// mcpVTPMClientVersion is the version of this MCP test client.
	mcpVTPMClientVersion = "1.0.0"
)

// MCP Tool names for vTPM operations.
const (
	// Bundle Tools
	MCPToolVTPMCreate   = "vtpm_create"
	MCPToolVTPMDelete   = "vtpm_delete"
	MCPToolVTPMList     = "vtpm_list"
	MCPToolVTPMGet      = "vtpm_get"
	MCPToolVTPMValidate = "vtpm_validate"
	MCPToolVTPMExport   = "vtpm_export"
	MCPToolVTPMImport   = "vtpm_import"

	// Template Tools
	MCPToolVTPMTemplateCreate = "vtpm_template_create"
	MCPToolVTPMTemplateGet    = "vtpm_template_get"
	MCPToolVTPMTemplateDelete = "vtpm_template_delete"
	MCPToolVTPMTemplateList   = "vtpm_template_list"
	MCPToolVTPMTemplateClone  = "vtpm_template_clone"

	// Path Tools
	MCPToolVTPMGetBundlePath    = "vtpm_get_bundle_path"
	MCPToolVTPMGetTPMSocketPath = "vtpm_get_tpm_socket_path"
	MCPToolVTPMGetNVRAMPath     = "vtpm_get_nvram_path"

	// Runtime TPM Tools
	MCPToolVTPMStart     = "vtpm_start"
	MCPToolVTPMStop      = "vtpm_stop"
	MCPToolVTPMIsRunning = "vtpm_is_running"
	MCPToolVTPMQuote     = "vtpm_quote"
	MCPToolVTPMSeal      = "vtpm_seal"
	MCPToolVTPMUnseal    = "vtpm_unseal"
	MCPToolVTPMExtendPCR = "vtpm_extend_pcr"
	MCPToolVTPMReadPCR   = "vtpm_read_pcr"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrMCPVTPMConnectionFailed indicates an MCP connection failure.
type ErrMCPVTPMConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrMCPVTPMConnectionFailed) Error() string {
	return fmt.Sprintf("MCP vTPM connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrMCPVTPMConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrMCPVTPMInitializeFailed indicates MCP initialization failure.
type ErrMCPVTPMInitializeFailed struct {
	Err error
}

func (e ErrMCPVTPMInitializeFailed) Error() string {
	return fmt.Sprintf("MCP vTPM initialization failed: %v", e.Err)
}

func (e ErrMCPVTPMInitializeFailed) Unwrap() error {
	return e.Err
}

// ErrMCPVTPMToolCallFailed indicates an MCP tool call failure.
type ErrMCPVTPMToolCallFailed struct {
	Tool    string
	Code    int
	Message string
}

func (e ErrMCPVTPMToolCallFailed) Error() string {
	return fmt.Sprintf("MCP vTPM tool call %s failed (code %d): %s", e.Tool, e.Code, e.Message)
}

// ErrMCPVTPMResponseParseFailed indicates MCP response parsing failure.
type ErrMCPVTPMResponseParseFailed struct {
	Tool string
	Err  error
}

func (e ErrMCPVTPMResponseParseFailed) Error() string {
	return fmt.Sprintf("MCP vTPM response parse failed for %s: %v", e.Tool, e.Err)
}

func (e ErrMCPVTPMResponseParseFailed) Unwrap() error {
	return e.Err
}

// ErrMCPVTPMClientClosed indicates the client is closed.
type ErrMCPVTPMClientClosed struct{}

func (e ErrMCPVTPMClientClosed) Error() string {
	return "MCP vTPM client is closed"
}

// ErrMCPVTPMRequestFailed indicates an MCP HTTP request failure.
type ErrMCPVTPMRequestFailed struct {
	Err error
}

func (e ErrMCPVTPMRequestFailed) Error() string {
	return fmt.Sprintf("MCP vTPM request failed: %v", e.Err)
}

func (e ErrMCPVTPMRequestFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// MCP JSON-RPC Types
// =============================================================================

// mcpVTPMRequest represents an MCP JSON-RPC request.
type mcpVTPMRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// mcpVTPMResponse represents an MCP JSON-RPC response.
type mcpVTPMResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcpVTPMError   `json:"error,omitempty"`
}

// mcpVTPMError represents an MCP JSON-RPC error.
type mcpVTPMError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// mcpVTPMCallToolParams represents parameters for tools/call.
type mcpVTPMCallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// mcpVTPMCallToolResult represents the result of tools/call.
type mcpVTPMCallToolResult struct {
	Content []mcpVTPMContent `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

// mcpVTPMContent represents content in an MCP response.
type mcpVTPMContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// mcpVTPMInitializeRequest represents the MCP initialize request params.
type mcpVTPMInitializeRequest struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ClientInfo      mcpVTPMClientInfo      `json:"clientInfo"`
}

// mcpVTPMClientInfo represents the MCP client info.
type mcpVTPMClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// =============================================================================
// MCP Response Types
// =============================================================================

type mcpBundleResp struct {
	ID                string            `json:"id"`
	Mode              string            `json:"mode"`
	Hostname          string            `json:"hostname"`
	EKAlgorithm       string            `json:"ek_algorithm"`
	SecureBootEnabled bool              `json:"secure_boot_enabled"`
	CreatedAt         string            `json:"created_at"`
	ClonedFrom        string            `json:"cloned_from,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
}

type mcpTemplateResp struct {
	ID                string `json:"id"`
	Description       string `json:"description"`
	TPMStateDir       string `json:"tpm_state_dir"`
	NVRAMPath         string `json:"nvram_path"`
	SecureBootKeysDir string `json:"secure_boot_keys_dir"`
	EKAlgorithm       string `json:"ek_algorithm"`
	SecureBootEnabled bool   `json:"secure_boot_enabled"`
	CreatedAt         string `json:"created_at"`
}

type mcpListTemplatesResp struct {
	Templates []*mcpTemplateResp `json:"templates"`
	Total     int                `json:"total"`
}

type mcpValidateResp struct {
	ID     string   `json:"id"`
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

type mcpPathResp struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

type mcpStartResp struct {
	BundleID   string `json:"bundle_id"`
	Running    bool   `json:"running"`
	SocketPath string `json:"socket_path"`
}

type mcpStopResp struct {
	BundleID string `json:"bundle_id"`
	Stopped  bool   `json:"stopped"`
}

type mcpIsRunningResp struct {
	BundleID string `json:"bundle_id"`
	Running  bool   `json:"running"`
}

type mcpQuoteResp struct {
	BundleID      string            `json:"bundle_id"`
	Quote         string            `json:"quote"`      // Base64 encoded
	Signature     string            `json:"signature"`  // Base64 encoded
	PCRValues     map[string]string `json:"pcr_values"` // PCR index -> Base64 value
	HashAlgorithm string            `json:"hash_algorithm"`
}

type mcpSealResp struct {
	BundleID   string `json:"bundle_id"`
	SealedData string `json:"sealed_data"` // Base64 encoded
}

type mcpUnsealResp struct {
	BundleID string `json:"bundle_id"`
	Data     string `json:"data"` // Base64 encoded
}

type mcpExtendPCRResp struct {
	BundleID string `json:"bundle_id"`
	PCRIndex int    `json:"pcr_index"`
	Extended bool   `json:"extended"`
}

type mcpReadPCRResp struct {
	BundleID string `json:"bundle_id"`
	PCRIndex int    `json:"pcr_index"`
	Value    string `json:"value"` // Base64 encoded
}

type mcpExportResp struct {
	ID       string `json:"id"`
	Data     string `json:"data"` // Base64 encoded
	Size     int64  `json:"size"`
	Checksum string `json:"checksum"`
}

type mcpImportResp struct {
	ID        string `json:"id"`
	Mode      string `json:"mode"`
	Hostname  string `json:"hostname"`
	CreatedAt string `json:"created_at"`
}

// =============================================================================
// MCP Adapter
// =============================================================================

// MCPAdapter implements VTPMCommands using the MCP protocol over HTTP transport.
// The adapter connects to the in-process MCP HTTP server started by setup_test.go.
// MCP (Model Context Protocol) is designed for AI/LLM integration.
type MCPAdapter struct {
	endpoint    string
	httpClient  *http.Client
	initialized bool
	requestID   int64
}

// NewMCPAdapter creates a new MCP adapter for vTPM integration testing.
// It reads the platformd MCP endpoint from the VTPM_MCP_ENDPOINT environment
// variable, which the integration harness exports; MCP is HTTPS only (#844).
func NewMCPAdapter() *MCPAdapter {
	endpoint := os.Getenv("VTPM_MCP_ENDPOINT")
	if endpoint == "" {
		endpoint = "127.0.0.1:9445"
	}

	return &MCPAdapter{
		endpoint:   helpers.MCPBaseURL(endpoint),
		httpClient: helpers.NewHTTPClient(DefaultMCPTimeoutVTPM),
	}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup initializes the MCP connection by performing the JSON-RPC initialize
// handshake with the MCP HTTP server.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	initReq := mcpVTPMInitializeRequest{
		ProtocolVersion: mcpVTPMProtocolVersion,
		Capabilities:    map[string]interface{}{},
		ClientInfo: mcpVTPMClientInfo{
			Name:    mcpVTPMClientName,
			Version: mcpVTPMClientVersion,
		},
	}

	var result json.RawMessage
	if err := m.sendRequest(ctx, "initialize", initReq, &result); err != nil {
		return ErrMCPVTPMInitializeFailed{Err: err}
	}

	m.initialized = true
	return nil
}

// Teardown closes the MCP connection and releases resources.
func (m *MCPAdapter) Teardown(ctx context.Context) error {
	if m.httpClient != nil {
		m.httpClient.CloseIdleConnections()
	}
	m.initialized = false
	return nil
}

// =============================================================================
// HTTP Transport Layer
// =============================================================================

// nextRequestID returns a monotonically increasing request ID for JSON-RPC.
func (m *MCPAdapter) nextRequestID() int64 {
	return atomic.AddInt64(&m.requestID, 1)
}

// sendRequest sends a JSON-RPC request over HTTP and decodes the response.
func (m *MCPAdapter) sendRequest(ctx context.Context, method string, params interface{}, result interface{}) error {
	req := mcpVTPMRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      m.nextRequestID(),
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return ErrMCPVTPMRequestFailed{Err: fmt.Errorf("failed to marshal request: %w", err)}
	}

	// Build the URL: endpoint already has scheme (http://host:port), append /mcp path
	url := m.endpoint + "/mcp"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return ErrMCPVTPMRequestFailed{Err: fmt.Errorf("failed to create HTTP request: %w", err)}
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return ErrMCPVTPMConnectionFailed{Endpoint: m.endpoint, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrMCPVTPMRequestFailed{Err: fmt.Errorf("failed to read response body: %w", err)}
	}

	var rpcResp mcpVTPMResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return ErrMCPVTPMResponseParseFailed{Tool: method, Err: err}
	}

	if rpcResp.Error != nil {
		return ErrMCPVTPMToolCallFailed{
			Tool:    method,
			Code:    rpcResp.Error.Code,
			Message: rpcResp.Error.Message,
		}
	}

	if result != nil && len(rpcResp.Result) > 0 {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return ErrMCPVTPMResponseParseFailed{Tool: method, Err: err}
		}
	}

	return nil
}

// callTool calls an MCP tool via the tools/call JSON-RPC method.
// It handles both MCP content-wrapped and raw map response formats.
func (m *MCPAdapter) callTool(ctx context.Context, name string, args map[string]interface{}) (*mcpVTPMCallToolResult, error) {
	params := mcpVTPMCallToolParams{
		Name:      name,
		Arguments: args,
	}

	var rawResult json.RawMessage
	if err := m.sendRequest(ctx, "tools/call", params, &rawResult); err != nil {
		return nil, ErrMCPVTPMToolCallFailed{Tool: name, Code: -1, Message: err.Error()}
	}

	// The tool output is JSON in the CallToolResult's text block.
	output, err := mcpwire.ToolOutputJSON(rawResult)
	if err != nil {
		return nil, ErrMCPVTPMToolCallFailed{Tool: name, Code: -1, Message: err.Error()}
	}
	return &mcpVTPMCallToolResult{
		Content: []mcpVTPMContent{{Type: "text", Text: string(output)}},
	}, nil
}

// parseToolResult parses the tool result content into the target struct.
func (m *MCPAdapter) parseToolResult(result *mcpVTPMCallToolResult, tool string, v interface{}) error {
	if len(result.Content) == 0 {
		return ErrMCPVTPMResponseParseFailed{Tool: tool, Err: fmt.Errorf("no content")}
	}

	for _, content := range result.Content {
		if content.Type == "text" && content.Text != "" {
			if err := json.Unmarshal([]byte(content.Text), v); err != nil {
				return ErrMCPVTPMResponseParseFailed{Tool: tool, Err: err}
			}
			return nil
		}
	}

	return ErrMCPVTPMResponseParseFailed{Tool: tool, Err: fmt.Errorf("no text content")}
}

// =============================================================================
// Bundle CRUD Commands
// =============================================================================

// CreateBundle creates a new vTPM bundle via MCP.
func (m *MCPAdapter) CreateBundle(ctx context.Context, opts CreateBundleOptions) (*CreateBundleResult, error) {
	args := map[string]interface{}{
		"name":      opts.Hostname,
		"algorithm": string(opts.EKAlgorithm),
	}
	if opts.Mode != "" {
		args["mode"] = string(opts.Mode)
	}
	if len(opts.Labels) > 0 {
		args["labels"] = opts.Labels
	}

	result, err := m.callTool(ctx, MCPToolVTPMCreate, args)
	if err != nil {
		return nil, err
	}

	var resp mcpBundleResp
	if err := m.parseToolResult(result, MCPToolVTPMCreate, &resp); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, resp.CreatedAt)
	bundle := &vtpm.Bundle{
		ID:        resp.ID,
		Mode:      vtpm.BundleMode(resp.Mode),
		CreatedAt: createdAt,
		Manifest: &vtpm.Manifest{
			Hostname:          resp.Hostname,
			EKAlgorithm:       vtpm.EKAlgorithm(resp.EKAlgorithm),
			SecureBootEnabled: resp.SecureBootEnabled,
			Labels:            resp.Labels,
		},
	}

	return &CreateBundleResult{Bundle: bundle}, nil
}

// GetBundle retrieves a bundle by ID via MCP.
func (m *MCPAdapter) GetBundle(ctx context.Context, opts GetBundleOptions) (*GetBundleResult, error) {
	args := map[string]interface{}{
		"name": opts.ID,
	}

	result, err := m.callTool(ctx, MCPToolVTPMGet, args)
	if err != nil {
		return nil, err
	}

	var resp mcpBundleResp
	if err := m.parseToolResult(result, MCPToolVTPMGet, &resp); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, resp.CreatedAt)
	bundle := &vtpm.Bundle{
		ID:         resp.ID,
		Mode:       vtpm.BundleMode(resp.Mode),
		ClonedFrom: resp.ClonedFrom,
		CreatedAt:  createdAt,
		Manifest: &vtpm.Manifest{
			Hostname:          resp.Hostname,
			EKAlgorithm:       vtpm.EKAlgorithm(resp.EKAlgorithm),
			SecureBootEnabled: resp.SecureBootEnabled,
			Labels:            resp.Labels,
		},
	}

	return &GetBundleResult{Bundle: bundle}, nil
}

// DeleteBundle deletes a bundle via MCP.
func (m *MCPAdapter) DeleteBundle(ctx context.Context, opts DeleteBundleOptions) (*DeleteBundleResult, error) {
	args := map[string]interface{}{
		"name": opts.ID,
	}

	result, err := m.callTool(ctx, MCPToolVTPMDelete, args)
	if err != nil {
		return nil, err
	}

	// The MCP server returns {"success": true} for delete operations.
	var resp map[string]interface{}
	if err := m.parseToolResult(result, MCPToolVTPMDelete, &resp); err != nil {
		return nil, err
	}

	success, _ := resp["success"].(bool)
	return &DeleteBundleResult{Success: success}, nil
}

// ListBundles lists bundles via MCP.
// The MCP server does not support pagination natively, so limit and offset
// are applied client-side after receiving the full result set.
func (m *MCPAdapter) ListBundles(ctx context.Context, opts ListBundlesOptions) (*ListBundlesResult, error) {
	args := map[string]interface{}{}
	if opts.Mode != "" {
		args["mode"] = string(opts.Mode)
	}

	result, err := m.callTool(ctx, MCPToolVTPMList, args)
	if err != nil {
		return nil, err
	}

	// The MCP server returns {"instances": [bundle1, bundle2, ...]}
	// where each bundle is a vtpm.Bundle serialized through marshalResult.
	// Parse the raw response to handle the "instances" key.
	var rawResp map[string]json.RawMessage
	if err := m.parseToolResult(result, MCPToolVTPMList, &rawResp); err != nil {
		return nil, err
	}

	instancesRaw, ok := rawResp["instances"]
	if !ok {
		return &ListBundlesResult{Bundles: nil, Total: 0}, nil
	}

	var instances []json.RawMessage
	if err := json.Unmarshal(instancesRaw, &instances); err != nil {
		return nil, ErrMCPVTPMResponseParseFailed{Tool: MCPToolVTPMList, Err: err}
	}

	allBundles := make([]*vtpm.Bundle, 0, len(instances))
	for _, raw := range instances {
		var b mcpBundleResp
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, ErrMCPVTPMResponseParseFailed{Tool: MCPToolVTPMList, Err: err}
		}
		createdAt, _ := time.Parse(time.RFC3339, b.CreatedAt)
		allBundles = append(allBundles, &vtpm.Bundle{
			ID:        b.ID,
			Mode:      vtpm.BundleMode(b.Mode),
			CreatedAt: createdAt,
			Manifest: &vtpm.Manifest{
				Hostname:          b.Hostname,
				EKAlgorithm:       vtpm.EKAlgorithm(b.EKAlgorithm),
				SecureBootEnabled: b.SecureBootEnabled,
			},
		})
	}

	total := len(allBundles)

	// Apply client-side offset
	if opts.Offset > 0 && opts.Offset < len(allBundles) {
		allBundles = allBundles[opts.Offset:]
	} else if opts.Offset >= len(allBundles) {
		allBundles = nil
	}

	// Apply client-side limit
	if opts.Limit > 0 && opts.Limit < len(allBundles) {
		allBundles = allBundles[:opts.Limit]
	}

	return &ListBundlesResult{
		Bundles: allBundles,
		Total:   total,
	}, nil
}

// =============================================================================
// Template CRUD Commands
// =============================================================================

// CreateTemplate creates a new vTPM template via MCP.
func (m *MCPAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	args := map[string]interface{}{
		"id":          opts.ID,
		"description": opts.Description,
		"algorithm":   string(opts.EKAlgorithm),
	}
	if opts.SecureBootEnabled {
		args["secure_boot"] = true
	}

	result, err := m.callTool(ctx, MCPToolVTPMTemplateCreate, args)
	if err != nil {
		return nil, err
	}

	var resp mcpTemplateResp
	if err := m.parseToolResult(result, MCPToolVTPMTemplateCreate, &resp); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, resp.CreatedAt)
	template := &vtpm.Template{
		ID:                resp.ID,
		Description:       resp.Description,
		TPMStateDir:       resp.TPMStateDir,
		NVRAMPath:         resp.NVRAMPath,
		SecureBootKeysDir: resp.SecureBootKeysDir,
		EKAlgorithm:       vtpm.EKAlgorithm(resp.EKAlgorithm),
		SecureBootEnabled: resp.SecureBootEnabled,
		CreatedAt:         createdAt,
	}

	return &CreateTemplateResult{Template: template}, nil
}

// GetTemplate retrieves a template by ID via MCP.
func (m *MCPAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	args := map[string]interface{}{
		"id": opts.ID,
	}

	result, err := m.callTool(ctx, MCPToolVTPMTemplateGet, args)
	if err != nil {
		return nil, err
	}

	var resp mcpTemplateResp
	if err := m.parseToolResult(result, MCPToolVTPMTemplateGet, &resp); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, resp.CreatedAt)
	template := &vtpm.Template{
		ID:                resp.ID,
		Description:       resp.Description,
		TPMStateDir:       resp.TPMStateDir,
		NVRAMPath:         resp.NVRAMPath,
		SecureBootKeysDir: resp.SecureBootKeysDir,
		EKAlgorithm:       vtpm.EKAlgorithm(resp.EKAlgorithm),
		SecureBootEnabled: resp.SecureBootEnabled,
		CreatedAt:         createdAt,
	}

	return &GetTemplateResult{Template: template}, nil
}

// DeleteTemplate deletes a template via MCP.
func (m *MCPAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	args := map[string]interface{}{
		"id": opts.ID,
	}

	result, err := m.callTool(ctx, MCPToolVTPMTemplateDelete, args)
	if err != nil {
		return nil, err
	}

	// The MCP server returns {"id": "...", "deleted": true} for template deletes.
	var resp map[string]interface{}
	if err := m.parseToolResult(result, MCPToolVTPMTemplateDelete, &resp); err != nil {
		return nil, err
	}

	deleted, _ := resp["deleted"].(bool)
	return &DeleteTemplateResult{Success: deleted}, nil
}

// ListTemplates lists templates via MCP.
func (m *MCPAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	args := map[string]interface{}{}

	result, err := m.callTool(ctx, MCPToolVTPMTemplateList, args)
	if err != nil {
		return nil, err
	}

	var resp mcpListTemplatesResp
	if err := m.parseToolResult(result, MCPToolVTPMTemplateList, &resp); err != nil {
		return nil, err
	}

	templates := make([]*vtpm.Template, len(resp.Templates))
	for i, t := range resp.Templates {
		createdAt, _ := time.Parse(time.RFC3339, t.CreatedAt)
		templates[i] = &vtpm.Template{
			ID:                t.ID,
			Description:       t.Description,
			EKAlgorithm:       vtpm.EKAlgorithm(t.EKAlgorithm),
			SecureBootEnabled: t.SecureBootEnabled,
			CreatedAt:         createdAt,
		}
	}

	return &ListTemplatesResult{
		Templates: templates,
		Total:     resp.Total,
	}, nil
}

// CloneTemplate clones a template to create a new bundle via MCP.
func (m *MCPAdapter) CloneTemplate(ctx context.Context, opts CloneTemplateOptions) (*CloneTemplateResult, error) {
	args := map[string]interface{}{
		"template_id": opts.TemplateID,
		"hostname":    opts.Hostname,
	}
	if len(opts.Labels) > 0 {
		args["labels"] = opts.Labels
	}

	result, err := m.callTool(ctx, MCPToolVTPMTemplateClone, args)
	if err != nil {
		return nil, err
	}

	var resp mcpBundleResp
	if err := m.parseToolResult(result, MCPToolVTPMTemplateClone, &resp); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, resp.CreatedAt)
	bundle := &vtpm.Bundle{
		ID:         resp.ID,
		Mode:       vtpm.BundleMode(resp.Mode),
		ClonedFrom: resp.ClonedFrom,
		CreatedAt:  createdAt,
		Manifest: &vtpm.Manifest{
			Hostname: resp.Hostname,
		},
	}

	return &CloneTemplateResult{Bundle: bundle}, nil
}

// =============================================================================
// Export/Import Commands
// =============================================================================

// ExportBundle exports a bundle to a tar.gz archive via MCP.
func (m *MCPAdapter) ExportBundle(ctx context.Context, opts ExportBundleOptions) (*ExportBundleResult, error) {
	args := map[string]interface{}{
		"name": opts.ID,
	}

	result, err := m.callTool(ctx, MCPToolVTPMExport, args)
	if err != nil {
		return nil, err
	}

	var resp mcpExportResp
	if err := m.parseToolResult(result, MCPToolVTPMExport, &resp); err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, ErrMCPVTPMResponseParseFailed{Tool: MCPToolVTPMExport, Err: err}
	}

	checksum := sha256.Sum256(data)
	exportResult := &ExportBundleResult{
		Size:     resp.Size,
		Checksum: hex.EncodeToString(checksum[:]),
	}

	// Write to the specified output path or a temp file so that
	// the ArchivePath is always populated for downstream import tests.
	archivePath := opts.OutputPath
	if archivePath == "" {
		tmpFile, tmpErr := os.CreateTemp("", "vtpm-export-*.tar.gz")
		if tmpErr != nil {
			return nil, ErrMCPVTPMRequestFailed{Err: fmt.Errorf("failed to create temp file: %w", tmpErr)}
		}
		archivePath = tmpFile.Name()
		tmpFile.Close()
	}
	if writeErr := os.WriteFile(archivePath, data, 0600); writeErr != nil {
		return nil, ErrMCPVTPMRequestFailed{Err: fmt.Errorf("failed to write export file: %w", writeErr)}
	}
	exportResult.ArchivePath = archivePath

	return exportResult, nil
}

// ImportBundle imports a bundle from a tar.gz archive via MCP.
func (m *MCPAdapter) ImportBundle(ctx context.Context, opts ImportBundleOptions) (*ImportBundleResult, error) {
	var data []byte

	if opts.ArchivePath != "" {
		var err error
		data, err = os.ReadFile(opts.ArchivePath)
		if err != nil {
			return nil, ErrMCPVTPMRequestFailed{Err: fmt.Errorf("failed to read archive: %w", err)}
		}
	} else if len(opts.ArchiveData) > 0 {
		data = opts.ArchiveData
	} else {
		return nil, ErrMCPVTPMRequestFailed{Err: fmt.Errorf("archive path or data required")}
	}

	args := map[string]interface{}{
		"data": base64.StdEncoding.EncodeToString(data),
	}

	result, err := m.callTool(ctx, MCPToolVTPMImport, args)
	if err != nil {
		return nil, err
	}

	var resp mcpImportResp
	if err := m.parseToolResult(result, MCPToolVTPMImport, &resp); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, resp.CreatedAt)
	bundle := &vtpm.Bundle{
		ID:        resp.ID,
		Mode:      vtpm.BundleMode(resp.Mode),
		CreatedAt: createdAt,
		Manifest: &vtpm.Manifest{
			Hostname: resp.Hostname,
		},
	}

	return &ImportBundleResult{Bundle: bundle}, nil
}

// =============================================================================
// Validation Commands
// =============================================================================

// ValidateBundle validates bundle integrity via MCP.
func (m *MCPAdapter) ValidateBundle(ctx context.Context, opts ValidateBundleOptions) (*ValidateBundleResult, error) {
	args := map[string]interface{}{
		"name": opts.ID,
	}

	result, err := m.callTool(ctx, MCPToolVTPMValidate, args)
	if err != nil {
		return nil, err
	}

	var resp mcpValidateResp
	if err := m.parseToolResult(result, MCPToolVTPMValidate, &resp); err != nil {
		return nil, err
	}

	return &ValidateBundleResult{
		Valid:            resp.Valid,
		Errors:           resp.Errors,
		ChecksumVerified: resp.Valid,
	}, nil
}

// =============================================================================
// Path Commands
// =============================================================================

// GetBundlePath returns the filesystem path to a bundle via MCP.
func (m *MCPAdapter) GetBundlePath(ctx context.Context, opts GetBundlePathOptions) (*GetBundlePathResult, error) {
	args := map[string]interface{}{
		"name": opts.ID,
	}

	result, err := m.callTool(ctx, MCPToolVTPMGetBundlePath, args)
	if err != nil {
		return nil, err
	}

	var resp mcpPathResp
	if err := m.parseToolResult(result, MCPToolVTPMGetBundlePath, &resp); err != nil {
		return nil, err
	}

	return &GetBundlePathResult{Path: resp.Path}, nil
}

// GetTPMSocketPath returns the TPM socket path for a bundle via MCP.
func (m *MCPAdapter) GetTPMSocketPath(ctx context.Context, opts GetTPMSocketPathOptions) (*GetTPMSocketPathResult, error) {
	args := map[string]interface{}{
		"name": opts.ID,
	}

	result, err := m.callTool(ctx, MCPToolVTPMGetTPMSocketPath, args)
	if err != nil {
		return nil, err
	}

	var resp mcpPathResp
	if err := m.parseToolResult(result, MCPToolVTPMGetTPMSocketPath, &resp); err != nil {
		return nil, err
	}

	return &GetTPMSocketPathResult{Path: resp.Path}, nil
}

// GetNVRAMPath returns the OVMF NVRAM path for a bundle via MCP.
func (m *MCPAdapter) GetNVRAMPath(ctx context.Context, opts GetNVRAMPathOptions) (*GetNVRAMPathResult, error) {
	args := map[string]interface{}{
		"name": opts.ID,
	}

	result, err := m.callTool(ctx, MCPToolVTPMGetNVRAMPath, args)
	if err != nil {
		return nil, err
	}

	var resp mcpPathResp
	if err := m.parseToolResult(result, MCPToolVTPMGetNVRAMPath, &resp); err != nil {
		return nil, err
	}

	return &GetNVRAMPathResult{Path: resp.Path}, nil
}

// =============================================================================
// Runtime TPM Commands
// =============================================================================

// Start starts the swtpm daemon for a bundle via MCP.
func (m *MCPAdapter) Start(ctx context.Context, opts StartOptions) (*StartResult, error) {
	args := map[string]interface{}{
		"name": opts.BundleID,
	}

	result, err := m.callTool(ctx, MCPToolVTPMStart, args)
	if err != nil {
		return nil, err
	}

	var resp mcpStartResp
	if err := m.parseToolResult(result, MCPToolVTPMStart, &resp); err != nil {
		return nil, err
	}

	return &StartResult{
		BundleID:   resp.BundleID,
		Running:    resp.Running,
		SocketPath: resp.SocketPath,
	}, nil
}

// Stop stops the swtpm daemon for a bundle via MCP.
func (m *MCPAdapter) Stop(ctx context.Context, opts StopOptions) (*StopResult, error) {
	args := map[string]interface{}{
		"name": opts.BundleID,
	}

	result, err := m.callTool(ctx, MCPToolVTPMStop, args)
	if err != nil {
		return nil, err
	}

	var resp mcpStopResp
	if err := m.parseToolResult(result, MCPToolVTPMStop, &resp); err != nil {
		return nil, err
	}

	return &StopResult{
		BundleID: resp.BundleID,
		Stopped:  resp.Stopped,
	}, nil
}

// IsRunning checks if the vTPM for a bundle is running via MCP.
func (m *MCPAdapter) IsRunning(ctx context.Context, opts IsRunningOptions) (*IsRunningResult, error) {
	args := map[string]interface{}{
		"name": opts.BundleID,
	}

	result, err := m.callTool(ctx, MCPToolVTPMIsRunning, args)
	if err != nil {
		return nil, err
	}

	var resp mcpIsRunningResp
	if err := m.parseToolResult(result, MCPToolVTPMIsRunning, &resp); err != nil {
		return nil, err
	}

	return &IsRunningResult{
		BundleID: resp.BundleID,
		Running:  resp.Running,
	}, nil
}

// Quote generates a TPM quote over specified PCRs via MCP.
func (m *MCPAdapter) Quote(ctx context.Context, opts QuoteOptions) (*QuoteResult, error) {
	args := map[string]interface{}{
		"name":  opts.BundleID,
		"nonce": base64.StdEncoding.EncodeToString(opts.Nonce),
		"pcrs":  opts.PCRs,
	}

	result, err := m.callTool(ctx, MCPToolVTPMQuote, args)
	if err != nil {
		return nil, err
	}

	var resp mcpQuoteResp
	if err := m.parseToolResult(result, MCPToolVTPMQuote, &resp); err != nil {
		return nil, err
	}

	quote, _ := base64.StdEncoding.DecodeString(resp.Quote)
	signature, _ := base64.StdEncoding.DecodeString(resp.Signature)

	pcrValues := make(map[int][]byte)
	for k, v := range resp.PCRValues {
		var idx int
		fmt.Sscanf(k, "%d", &idx)
		decoded, _ := base64.StdEncoding.DecodeString(v)
		pcrValues[idx] = decoded
	}

	return &QuoteResult{
		BundleID:      resp.BundleID,
		Quote:         quote,
		Signature:     signature,
		PCRValues:     pcrValues,
		HashAlgorithm: resp.HashAlgorithm,
	}, nil
}

// Seal encrypts data to the TPM via MCP.
func (m *MCPAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	args := map[string]interface{}{
		"name": opts.BundleID,
		"data": base64.StdEncoding.EncodeToString(opts.Data),
	}
	if len(opts.PCRs) > 0 {
		args["pcrs"] = opts.PCRs
	}
	if opts.AuthValue != "" {
		args["auth_value"] = opts.AuthValue
	}

	result, err := m.callTool(ctx, MCPToolVTPMSeal, args)
	if err != nil {
		return nil, err
	}

	var resp mcpSealResp
	if err := m.parseToolResult(result, MCPToolVTPMSeal, &resp); err != nil {
		return nil, err
	}

	sealedData, _ := base64.StdEncoding.DecodeString(resp.SealedData)

	return &SealResult{
		BundleID:   resp.BundleID,
		SealedData: sealedData,
	}, nil
}

// Unseal decrypts data from the TPM via MCP.
func (m *MCPAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	args := map[string]interface{}{
		"name":   opts.BundleID,
		"sealed": base64.StdEncoding.EncodeToString(opts.SealedData),
	}
	if opts.AuthValue != "" {
		args["auth_value"] = opts.AuthValue
	}

	result, err := m.callTool(ctx, MCPToolVTPMUnseal, args)
	if err != nil {
		return nil, err
	}

	var resp mcpUnsealResp
	if err := m.parseToolResult(result, MCPToolVTPMUnseal, &resp); err != nil {
		return nil, err
	}

	data, _ := base64.StdEncoding.DecodeString(resp.Data)

	return &UnsealResult{
		BundleID: resp.BundleID,
		Data:     data,
	}, nil
}

// ExtendPCR extends a PCR with the provided data via MCP.
func (m *MCPAdapter) ExtendPCR(ctx context.Context, opts ExtendPCROptions) (*ExtendPCRResult, error) {
	args := map[string]interface{}{
		"name": opts.BundleID,
		"pcr":  opts.PCRIndex,
		"data": base64.StdEncoding.EncodeToString(opts.Data),
	}

	result, err := m.callTool(ctx, MCPToolVTPMExtendPCR, args)
	if err != nil {
		return nil, err
	}

	var resp mcpExtendPCRResp
	if err := m.parseToolResult(result, MCPToolVTPMExtendPCR, &resp); err != nil {
		return nil, err
	}

	return &ExtendPCRResult{
		BundleID: resp.BundleID,
		PCRIndex: resp.PCRIndex,
		Extended: resp.Extended,
	}, nil
}

// ReadPCR reads the current value of a PCR via MCP.
func (m *MCPAdapter) ReadPCR(ctx context.Context, opts ReadPCROptions) (*ReadPCRResult, error) {
	args := map[string]interface{}{
		"name": opts.BundleID,
		"pcr":  opts.PCRIndex,
	}

	result, err := m.callTool(ctx, MCPToolVTPMReadPCR, args)
	if err != nil {
		return nil, err
	}

	var resp mcpReadPCRResp
	if err := m.parseToolResult(result, MCPToolVTPMReadPCR, &resp); err != nil {
		return nil, err
	}

	value, _ := base64.StdEncoding.DecodeString(resp.Value)

	return &ReadPCRResult{
		BundleID: resp.BundleID,
		PCRIndex: resp.PCRIndex,
		Value:    value,
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure MCPAdapter implements VTPMCommands interface.
var _ VTPMCommands = (*MCPAdapter)(nil)
