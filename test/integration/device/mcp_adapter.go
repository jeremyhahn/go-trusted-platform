//go:build integration

package device

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// MCPAdapterError represents an error from the MCP adapter
type MCPAdapterError struct {
	Operation string
	Code      int
	Message   string
}

func (e *MCPAdapterError) Error() string {
	return fmt.Sprintf("MCP adapter error [%s]: %s (code: %d)", e.Operation, e.Message, e.Code)
}

// ErrMCPNotImplemented indicates a method is not yet implemented for MCP.
type ErrMCPNotImplemented struct {
	Method string
}

func (e ErrMCPNotImplemented) Error() string {
	return fmt.Sprintf("MCP method %s not implemented", e.Method)
}

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

// JSONRPCError represents a JSON-RPC 2.0 error
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// ToolCallParams represents MCP tool call parameters
type ToolCallParams struct {
	Name      string      `json:"name"`
	Arguments interface{} `json:"arguments"`
}

// MCPAdapter implements DeviceCommands using MCP (Model Context Protocol)
type MCPAdapter struct {
	endpoint  string
	client    *http.Client
	requestID int64
}

// NewMCPAdapter creates a new MCP adapter
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{
		endpoint: GetMCPEndpoint(),
		client:   helpers.NewHTTPClient(30 * time.Second),
	}
}

// Setup prepares the adapter for testing
func (a *MCPAdapter) Setup(ctx context.Context) error {
	// Verify endpoint is reachable with initialize request
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "device-integration-test",
				"version": "1.0.0",
			},
		},
		ID: atomic.AddInt64(&a.requestID, 1),
	}

	_, err := a.doRequest(ctx, req)
	if err != nil {
		return &MCPAdapterError{
			Operation: "Setup",
			Message:   "failed to initialize: " + err.Error(),
		}
	}

	return nil
}

// Teardown cleans up after testing
func (a *MCPAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name
func (a *MCPAdapter) Name() string {
	return "MCP"
}

// doRequest performs a JSON-RPC request and returns the response
func (a *MCPAdapter) doRequest(ctx context.Context, req JSONRPCRequest) (json.RawMessage, error) {
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "failed to marshal request: " + err.Error(),
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(reqData))
	if err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "failed to create request: " + err.Error(),
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "request failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "failed to read response: " + err.Error(),
		}
	}

	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(respData, &rpcResp); err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	if rpcResp.Error != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Code:      rpcResp.Error.Code,
			Message:   rpcResp.Error.Message,
		}
	}

	return rpcResp.Result, nil
}

// callTool invokes an MCP tool and returns the result
func (a *MCPAdapter) callTool(ctx context.Context, toolName string, args interface{}) (json.RawMessage, error) {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params: ToolCallParams{
			Name:      toolName,
			Arguments: args,
		},
		ID: atomic.AddInt64(&a.requestID, 1),
	}

	return a.doRequest(ctx, req)
}

// ============================================================================
// Device CRUD Operations
// ============================================================================

// RegisterDevice registers a new device
func (a *MCPAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	result, err := a.callTool(ctx, "device_register", opts)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(result, &device); err != nil {
		return nil, &MCPAdapterError{
			Operation: "RegisterDevice",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &RegisterDeviceResult{Device: &device}, nil
}

// GetDevice retrieves a device by its key
func (a *MCPAdapter) GetDevice(ctx context.Context, opts GetDeviceOptions) (*GetDeviceResult, error) {
	result, err := a.callTool(ctx, "device_get", opts)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(result, &device); err != nil {
		return nil, &MCPAdapterError{
			Operation: "GetDevice",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &GetDeviceResult{Device: &device}, nil
}

// UpdateDevice updates an existing device
func (a *MCPAdapter) UpdateDevice(ctx context.Context, opts UpdateDeviceOptions) (*UpdateDeviceResult, error) {
	result, err := a.callTool(ctx, "device_update", opts)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(result, &device); err != nil {
		return nil, &MCPAdapterError{
			Operation: "UpdateDevice",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &UpdateDeviceResult{Device: &device}, nil
}

// DeleteDevice removes a device
func (a *MCPAdapter) DeleteDevice(ctx context.Context, opts DeleteDeviceOptions) (*DeleteDeviceResult, error) {
	_, err := a.callTool(ctx, "device_delete", opts)
	if err != nil {
		return nil, err
	}

	return &DeleteDeviceResult{Success: true}, nil
}

// ListDevices lists all devices with optional filtering
func (a *MCPAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	result, err := a.callTool(ctx, "device_list", opts)
	if err != nil {
		return nil, err
	}

	var listResult ListDevicesResult
	if err := json.Unmarshal(result, &listResult); err != nil {
		var devices []*entities.Device
		if err := json.Unmarshal(result, &devices); err != nil {
			return nil, &MCPAdapterError{
				Operation: "ListDevices",
				Message:   "failed to parse response: " + err.Error(),
			}
		}
		listResult.Devices = devices
		listResult.Total = len(devices)
	}

	return &listResult, nil
}

// ============================================================================
// Device Lookups
// ============================================================================

// FindBySerial finds a device by its serial number
func (a *MCPAdapter) FindBySerial(ctx context.Context, opts FindBySerialOptions) (*FindBySerialResult, error) {
	result, err := a.callTool(ctx, "device_find_by_serial", opts)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(result, &device); err != nil {
		return nil, &MCPAdapterError{
			Operation: "FindBySerial",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &FindBySerialResult{Device: &device}, nil
}

// ============================================================================
// Profile CRUD Operations
// ============================================================================

// CreateProfile creates a new device profile
func (a *MCPAdapter) CreateProfile(ctx context.Context, opts CreateProfileOptions) (*CreateProfileResult, error) {
	result, err := a.callTool(ctx, "device_profile_create", opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(result, &profile); err != nil {
		return nil, &MCPAdapterError{
			Operation: "CreateProfile",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &CreateProfileResult{Profile: &profile}, nil
}

// GetProfile retrieves a profile by its key
func (a *MCPAdapter) GetProfile(ctx context.Context, opts GetProfileOptions) (*GetProfileResult, error) {
	result, err := a.callTool(ctx, "device_profile_get", opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(result, &profile); err != nil {
		return nil, &MCPAdapterError{
			Operation: "GetProfile",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &GetProfileResult{Profile: &profile}, nil
}

// UpdateProfile updates an existing profile
func (a *MCPAdapter) UpdateProfile(ctx context.Context, opts UpdateProfileOptions) (*UpdateProfileResult, error) {
	result, err := a.callTool(ctx, "device_profile_update", opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(result, &profile); err != nil {
		return nil, &MCPAdapterError{
			Operation: "UpdateProfile",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &UpdateProfileResult{Profile: &profile}, nil
}

// DeleteProfile removes a profile
func (a *MCPAdapter) DeleteProfile(ctx context.Context, opts DeleteProfileOptions) (*DeleteProfileResult, error) {
	_, err := a.callTool(ctx, "device_profile_delete", opts)
	if err != nil {
		return nil, err
	}

	return &DeleteProfileResult{Success: true}, nil
}

// ListProfiles lists all profiles with optional filtering
func (a *MCPAdapter) ListProfiles(ctx context.Context, opts ListProfilesOptions) (*ListProfilesResult, error) {
	result, err := a.callTool(ctx, "device_profile_list", opts)
	if err != nil {
		return nil, err
	}

	var listResult ListProfilesResult
	if err := json.Unmarshal(result, &listResult); err != nil {
		var profiles []*entities.DeviceProfile
		if err := json.Unmarshal(result, &profiles); err != nil {
			return nil, &MCPAdapterError{
				Operation: "ListProfiles",
				Message:   "failed to parse response: " + err.Error(),
			}
		}
		listResult.Profiles = profiles
		listResult.Total = len(profiles)
	}

	return &listResult, nil
}

// ============================================================================
// Profile Lookups
// ============================================================================

// FindProfileByMACAddress finds a profile by MAC address prefix
func (a *MCPAdapter) FindProfileByMACAddress(ctx context.Context, opts FindProfileByMACAddressOptions) (*FindProfileByMACAddressResult, error) {
	result, err := a.callTool(ctx, "device_profile_find_by_mac", opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(result, &profile); err != nil {
		return nil, &MCPAdapterError{
			Operation: "FindProfileByMACAddress",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &FindProfileByMACAddressResult{Profile: &profile}, nil
}

// FindProfileBySerial finds a profile by serial pattern
func (a *MCPAdapter) FindProfileBySerial(ctx context.Context, opts FindProfileBySerialOptions) (*FindProfileBySerialResult, error) {
	result, err := a.callTool(ctx, "device_profile_find_by_serial", opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(result, &profile); err != nil {
		return nil, &MCPAdapterError{
			Operation: "FindProfileBySerial",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &FindProfileBySerialResult{Profile: &profile}, nil
}

// FindMatchingProfile finds a profile matching device attributes
func (a *MCPAdapter) FindMatchingProfile(ctx context.Context, opts FindMatchingProfileOptions) (*FindMatchingProfileResult, error) {
	result, err := a.callTool(ctx, "device_profile_find_matching", opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(result, &profile); err != nil {
		return nil, &MCPAdapterError{
			Operation: "FindMatchingProfile",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &FindMatchingProfileResult{Profile: &profile}, nil
}

// ============================================================================
// Attestation
// ============================================================================

// AttestDevice performs device attestation
func (a *MCPAdapter) AttestDevice(ctx context.Context, opts AttestDeviceOptions) (*AttestDeviceResult, error) {
	result, err := a.callTool(ctx, "device_attest", opts)
	if err != nil {
		return nil, err
	}

	var attestResult AttestDeviceResult
	if err := json.Unmarshal(result, &attestResult); err != nil {
		return nil, &MCPAdapterError{
			Operation: "AttestDevice",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &attestResult, nil
}

// ============================================================================
// Template CRUD Operations (not yet available via MCP)
// ============================================================================

// CreateTemplate creates a new device template via MCP.
func (a *MCPAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	return nil, ErrMCPNotImplemented{Method: "CreateTemplate"}
}

// GetTemplate retrieves a template by ID via MCP.
func (a *MCPAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	return nil, ErrMCPNotImplemented{Method: "GetTemplate"}
}

// UpdateTemplate updates an existing template via MCP.
func (a *MCPAdapter) UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error) {
	return nil, ErrMCPNotImplemented{Method: "UpdateTemplate"}
}

// DeleteTemplate removes a template via MCP.
func (a *MCPAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	return nil, ErrMCPNotImplemented{Method: "DeleteTemplate"}
}

// ListTemplates lists all templates via MCP.
func (a *MCPAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	return nil, ErrMCPNotImplemented{Method: "ListTemplates"}
}

// CreateProfileFromTemplate creates a profile from a template via MCP.
func (a *MCPAdapter) CreateProfileFromTemplate(ctx context.Context, opts CreateProfileFromTemplateOptions) (*CreateProfileResult, error) {
	return nil, ErrMCPNotImplemented{Method: "CreateProfileFromTemplate"}
}

// FindConfigForDevice finds the config for a device via MCP.
func (a *MCPAdapter) FindConfigForDevice(ctx context.Context, opts FindConfigForDeviceOptions) (*FindConfigForDeviceResult, error) {
	return nil, ErrMCPNotImplemented{Method: "FindConfigForDevice"}
}

// AssignProfileToDevice assigns a profile to a device via MCP.
func (a *MCPAdapter) AssignProfileToDevice(ctx context.Context, opts AssignProfileToDeviceOptions) (*AssignProfileToDeviceResult, error) {
	return nil, ErrMCPNotImplemented{Method: "AssignProfileToDevice"}
}

// Verify MCPAdapter implements DeviceCommands
var _ DeviceCommands = (*MCPAdapter)(nil)
