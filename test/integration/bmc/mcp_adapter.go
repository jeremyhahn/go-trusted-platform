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

// This file implements the BMCCommands interface using the MCP (Model Context Protocol).
// General BMC operations are not yet wired to the MCP transport layer; Setup returns
// surface.ErrNoSurface so the test runner skips those subtests gracefully.
// EnrollBMC and RestoreBMC are fully implemented via the platform_bmc_enroll and
// platform_bmc_cert_restore MCP tools respectively.

//go:build integration

package bmc_integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"

	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// MCP tool name constants, matching pkg/api/mcp/bmc_tools.go.
const (
	mcpBMCToolEnroll  = "platform_bmc_enroll"
	mcpBMCToolRestore = "platform_bmc_cert_restore"
)

// =============================================================================
// MCP Protocol Adapter
// =============================================================================

// MCPAdapter implements BMCCommands using the MCP (Model Context Protocol).
// General BMC operations are not yet wired to the MCP transport layer; all
// such methods return surface.ErrNoSurface. EnrollBMC and RestoreBMC are
// fully implemented via the MCP tools listed above.
type MCPAdapter struct {
	endpoint   string
	httpClient *http.Client
	requestID  int64
}

// NewMCPAdapter creates a new MCP adapter for BMC integration testing.
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup returns surface.ErrNoSurface because the general BMC service is not
// yet exposed over the MCP transport. EnrollBMC and RestoreBMC connect
// independently on first use.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	return surface.ErrNoSurface{Transport: "MCP", Operation: "Setup"}
}

// Teardown closes idle HTTP connections.
func (m *MCPAdapter) Teardown() error {
	if m.httpClient != nil {
		m.httpClient.CloseIdleConnections()
	}
	return nil
}

// initClient initialises the HTTP client and MCP endpoint if not done yet.
// It performs the JSON-RPC initialize handshake required by the MCP protocol.
func (m *MCPAdapter) initClient(ctx context.Context) error {
	if m.httpClient != nil {
		return nil
	}
	endpoint := os.Getenv(EnvPlatformMCPEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformMCP
	}
	m.endpoint = helpers.MCPBaseURL(endpoint)
	m.httpClient = helpers.NewHTTPClient(DefaultRESTTimeout)

	initParams := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    "bmc-integration-test",
			"version": "1.0.0",
		},
	}
	var raw json.RawMessage
	if err := m.rpc(ctx, "initialize", initParams, &raw); err != nil {
		m.httpClient = nil
		return ErrMCPConnectionFailed{Endpoint: m.endpoint, Err: err}
	}
	return nil
}

// =============================================================================
// JSON-RPC helpers (mirrors ceremony MCP adapter pattern)
// =============================================================================

type mcpJSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type mcpJSONRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      int64            `json:"id"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *mcpJSONRPCError `json:"error,omitempty"`
}

type mcpJSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpCallToolResult struct {
	Content []mcpContentItem `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

type mcpContentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// rpc sends a JSON-RPC 2.0 request and decodes the result into out.
func (m *MCPAdapter) rpc(ctx context.Context, method string, params interface{}, out interface{}) error {
	body := mcpJSONRPCRequest{
		JSONRPC: "2.0",
		ID:      atomic.AddInt64(&m.requestID, 1),
		Method:  method,
		Params:  params,
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint+"/mcp", bytes.NewReader(buf))
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
	var envelope mcpJSONRPCResponse
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return fmt.Errorf("mcp parse: %w (body=%s)", err, string(respBody))
	}
	if envelope.Error != nil {
		return fmt.Errorf("mcp error %d: %s", envelope.Error.Code, envelope.Error.Message)
	}
	if out != nil && len(envelope.Result) > 0 {
		return json.Unmarshal(envelope.Result, out)
	}
	return nil
}

// callTool invokes a tools/call for name + args and decodes the first text
// content body into out.
func (m *MCPAdapter) callTool(ctx context.Context, name string, args map[string]interface{}, out interface{}) error {
	params := map[string]interface{}{
		"name":      name,
		"arguments": args,
	}
	var raw json.RawMessage
	if err := m.rpc(ctx, "tools/call", params, &raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	var result mcpCallToolResult
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Content) == 0 {
		// Some servers return the result map directly without the content wrapper.
		if out != nil {
			return json.Unmarshal(raw, out)
		}
		return nil
	}
	if result.IsError {
		msg := ""
		if len(result.Content) > 0 {
			msg = result.Content[0].Text
		}
		return fmt.Errorf("mcp tool %s error: %s", name, msg)
	}
	if out == nil {
		return nil
	}
	for _, item := range result.Content {
		if item.Type == "text" && item.Text != "" {
			return json.Unmarshal([]byte(item.Text), out)
		}
	}
	return nil
}

// =============================================================================
// Stub Operations (general BMC MCP surface not yet wired)
// =============================================================================

// PowerOn is not implemented for MCP.
func (m *MCPAdapter) PowerOn(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "PowerOn"}
}

// PowerOff is not implemented for MCP.
func (m *MCPAdapter) PowerOff(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "PowerOff"}
}

// PowerStatus is not implemented for MCP.
func (m *MCPAdapter) PowerStatus(ctx context.Context, profileID uint64) (bmcsvc.PowerState, error) {
	return bmcsvc.PowerStateUnspecified, surface.ErrNoSurface{Transport: "MCP", Operation: "PowerStatus"}
}

// SetBootDevice is not implemented for MCP.
func (m *MCPAdapter) SetBootDevice(ctx context.Context, profileID uint64, device bmcsvc.BootDevice, persistent bool) error {
	return surface.ErrNoSurface{Transport: "MCP", Operation: "SetBootDevice"}
}

// GetBootDevice is not implemented for MCP.
func (m *MCPAdapter) GetBootDevice(ctx context.Context, profileID uint64) (bmcsvc.BootDevice, error) {
	return bmcsvc.BootDeviceUnspecified, surface.ErrNoSurface{Transport: "MCP", Operation: "GetBootDevice"}
}

// MountISO is not implemented for MCP.
func (m *MCPAdapter) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	return surface.ErrNoSurface{Transport: "MCP", Operation: "MountISO"}
}

// UnmountISO is not implemented for MCP.
func (m *MCPAdapter) UnmountISO(ctx context.Context, profileID uint64) error {
	return surface.ErrNoSurface{Transport: "MCP", Operation: "UnmountISO"}
}

// VirtualMediaStatus is not implemented for MCP.
func (m *MCPAdapter) VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmcsvc.VirtualMediaInfo, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "VirtualMediaStatus"}
}

// GetSensors is not implemented for MCP.
func (m *MCPAdapter) GetSensors(ctx context.Context, profileID uint64) ([]bmcsvc.SensorReading, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "GetSensors"}
}

// GetSystemInfo is not implemented for MCP.
func (m *MCPAdapter) GetSystemInfo(ctx context.Context, profileID uint64) (*bmcsvc.SystemInfo, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "GetSystemInfo"}
}

// GetWebCertificate is not implemented for MCP.
func (m *MCPAdapter) GetWebCertificate(ctx context.Context, profileID uint64) (*bmcsvc.CertificateInfo, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "GetWebCertificate"}
}

// ListUsers is not implemented for MCP.
func (m *MCPAdapter) ListUsers(ctx context.Context, profileID uint64) ([]bmcsvc.User, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "ListUsers"}
}

// =============================================================================
// Enrollment Operations
// =============================================================================

// EnrollBMC runs the BMC enrollment ceremony via the platform_bmc_enroll MCP
// tool. The tool result is a JSON map returned inside a text content item;
// it is parsed into the local EnrollResult domain type.
func (m *MCPAdapter) EnrollBMC(ctx context.Context, profileID uint64, opts *EnrollOptions) (*EnrollResult, error) {
	if err := m.initClient(ctx); err != nil {
		return nil, err
	}

	args := map[string]interface{}{
		"profile_id": profileID,
	}
	if opts != nil {
		if opts.ReplaceCertificate != nil {
			args["replace_certificate"] = *opts.ReplaceCertificate
		}
		if opts.RotatePassword != nil {
			args["rotate_password"] = *opts.RotatePassword
		}
		if opts.DNSRegister != nil {
			args["dns_register"] = *opts.DNSRegister
		}
		if opts.DANEPublish != nil {
			args["dane_publish"] = *opts.DANEPublish
		}
	}

	var raw json.RawMessage
	if err := m.callTool(ctx, mcpBMCToolEnroll, args, &raw); err != nil {
		return nil, ErrMCPCallFailed{Tool: mcpBMCToolEnroll, Err: err}
	}
	return mcpEnrollResultToDomain(raw)
}

// mcpEnrollResultToDomain parses the JSON map returned by the
// platform_bmc_enroll MCP tool into the local EnrollResult type.
// The server-side shape is defined in pkg/api/daemon/mcp_bmc.go
// (BMCEnrollBMC). DeviceID arrives as a float64 from JSON; it is
// cast to uint64 explicitly.
func mcpEnrollResultToDomain(raw json.RawMessage) (*EnrollResult, error) {
	if len(raw) == 0 {
		return &EnrollResult{}, nil
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("mcp enroll: parse result: %w", err)
	}

	result := &EnrollResult{}

	// device_id arrives as a JSON number (float64).
	if v, ok := m["device_id"]; ok {
		var f float64
		if err := json.Unmarshal(v, &f); err == nil {
			result.DeviceID = uint64(f)
		}
	}
	mcpUnmarshalString(m, "endpoint", &result.Endpoint)
	mcpUnmarshalString(m, "hostname", &result.Hostname)
	mcpUnmarshalString(m, "dns_name", &result.DNSName)
	mcpUnmarshalString(m, "pin_spki_sha256", &result.PinSPKISHA256)

	// factory_cert_meta sub-object
	if v, ok := m["factory_cert_meta"]; ok {
		var meta map[string]json.RawMessage
		if err := json.Unmarshal(v, &meta); err == nil {
			mcpUnmarshalString(meta, "subject", &result.FactoryCertMeta.Subject)
			mcpUnmarshalString(meta, "issuer", &result.FactoryCertMeta.Issuer)
			mcpUnmarshalString(meta, "serial_number", &result.FactoryCertMeta.SerialNumber)
			mcpUnmarshalString(meta, "spki_sha256", &result.FactoryCertMeta.SPKISHA256)
			mcpUnmarshalString(meta, "sha256", &result.FactoryCertMeta.SHA256)
		}
	}

	// steps array
	if v, ok := m["steps"]; ok {
		var rawSteps []map[string]json.RawMessage
		if err := json.Unmarshal(v, &rawSteps); err == nil {
			result.Steps = make([]EnrollStep, 0, len(rawSteps))
			for _, rs := range rawSteps {
				var step EnrollStep
				mcpUnmarshalString(rs, "name", &step.Name)
				mcpUnmarshalString(rs, "detail", &step.Detail)
				if okV, ok2 := rs["ok"]; ok2 {
					var b bool
					if err := json.Unmarshal(okV, &b); err == nil {
						step.OK = b
					}
				}
				result.Steps = append(result.Steps, step)
			}
		}
	}

	return result, nil
}

// =============================================================================
// Factory Certificate Restore Operations
// =============================================================================

// RestoreBMC runs the BMC factory-certificate restore ceremony via the
// platform_bmc_cert_restore MCP tool. The tool result is a JSON map returned
// inside a text content item; it is parsed into the local RestoreResult type.
// The server-side response shape is defined in pkg/api/daemon/mcp_bmc.go
// (BMCRestoreFactoryCert). DeviceID arrives as a float64; it is cast to uint64.
func (m *MCPAdapter) RestoreBMC(ctx context.Context, profileID uint64) (*RestoreResult, error) {
	if err := m.initClient(ctx); err != nil {
		return nil, err
	}

	args := map[string]interface{}{
		"profile_id": profileID,
	}

	var raw json.RawMessage
	if err := m.callTool(ctx, mcpBMCToolRestore, args, &raw); err != nil {
		return nil, ErrMCPCallFailed{Tool: mcpBMCToolRestore, Err: err}
	}
	return mcpRestoreResultToDomain(raw)
}

// mcpRestoreResultToDomain parses the JSON map returned by the
// platform_bmc_cert_restore MCP tool into the local RestoreResult type.
// The server serialises device_id as a plain JSON number (float64); it is
// converted to uint64 explicitly to preserve full precision.
func mcpRestoreResultToDomain(raw json.RawMessage) (*RestoreResult, error) {
	if len(raw) == 0 {
		return &RestoreResult{}, nil
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("mcp restore: parse result: %w", err)
	}

	result := &RestoreResult{}

	// device_id arrives as a JSON number (float64).
	if v, ok := m["device_id"]; ok {
		var f float64
		if err := json.Unmarshal(v, &f); err == nil {
			result.DeviceID = uint64(f)
		}
	}
	mcpUnmarshalString(m, "endpoint", &result.Endpoint)
	mcpUnmarshalString(m, "hostname", &result.Hostname)

	// new_cert_meta sub-object
	if v, ok := m["new_cert_meta"]; ok {
		var meta map[string]json.RawMessage
		if err := json.Unmarshal(v, &meta); err == nil {
			mcpUnmarshalString(meta, "subject", &result.NewCertMeta.Subject)
			mcpUnmarshalString(meta, "issuer", &result.NewCertMeta.Issuer)
			mcpUnmarshalString(meta, "serial_number", &result.NewCertMeta.SerialNumber)
			mcpUnmarshalString(meta, "spki_sha256", &result.NewCertMeta.SPKISHA256)
			mcpUnmarshalString(meta, "sha256", &result.NewCertMeta.SHA256)
		}
	}

	// steps array
	if v, ok := m["steps"]; ok {
		var rawSteps []map[string]json.RawMessage
		if err := json.Unmarshal(v, &rawSteps); err == nil {
			result.Steps = make([]EnrollStep, 0, len(rawSteps))
			for _, rs := range rawSteps {
				var step EnrollStep
				mcpUnmarshalString(rs, "name", &step.Name)
				mcpUnmarshalString(rs, "detail", &step.Detail)
				if okV, ok2 := rs["ok"]; ok2 {
					var b bool
					if err := json.Unmarshal(okV, &b); err == nil {
						step.OK = b
					}
				}
				result.Steps = append(result.Steps, step)
			}
		}
	}

	return result, nil
}

// mcpUnmarshalString decodes a JSON string field from the raw map into dst,
// silently ignoring missing or non-string values.
func mcpUnmarshalString(m map[string]json.RawMessage, key string, dst *string) {
	v, ok := m[key]
	if !ok {
		return
	}
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		*dst = s
	}
}

// Ensure MCPAdapter implements BMCCommands interface.
var _ BMCCommands = (*MCPAdapter)(nil)
