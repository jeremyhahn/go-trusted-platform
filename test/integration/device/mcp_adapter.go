//go:build integration

package device

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
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

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, helpers.MCPEndpointURL(a.endpoint), bytes.NewReader(reqData))
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

// RecordAttestCert records the device's attestation certificate via the
// device_record_attest_cert tool.
func (a *MCPAdapter) RecordAttestCert(ctx context.Context, opts RecordAttestCertOptions) (*RecordAttestCertResult, error) {
	result, err := a.callTool(ctx, "device_record_attest_cert", map[string]interface{}{
		"device_id":        opts.DeviceID,
		"reissue":          opts.Reissue,
		"clear_on_refusal": opts.ClearOnRefusal,
	})
	if err != nil {
		return nil, err
	}

	var out RecordAttestCertResult
	if err := json.Unmarshal(result, &out); err != nil {
		return nil, &MCPAdapterError{
			Operation: "RecordAttestCert",
			Message:   "failed to parse response: " + err.Error(),
		}
	}
	return &out, nil
}

// AttestDevice submits quote evidence to the device_attest tool and returns
// the platform's verdict. The tool takes device_id plus base64 evidence;
// this adapter previously handed it the whole options struct, so neither of
// the arguments it declares was populated (#403).
func (a *MCPAdapter) AttestDevice(ctx context.Context, opts AttestDeviceOptions) (*AttestDeviceResult, error) {
	result, err := a.callTool(ctx, "device_attest", map[string]string{
		"device_id": opts.DeviceID,
		"evidence":  base64.StdEncoding.EncodeToString(opts.Evidence),
	})
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
	if attestResult.DeviceID == "" {
		attestResult.DeviceID = opts.DeviceID
	}

	return &attestResult, nil
}

// ============================================================================
// Template CRUD Operations (not yet available via MCP)
// ============================================================================

// CreateTemplate creates a new device template via MCP.
//
// The device_template_create tool takes and returns the config as YAML
// text, while the entity carries it as bytes.
func (a *MCPAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	args := map[string]interface{}{
		"tenant_id":   opts.TenantID,
		"name":        opts.Name,
		"description": opts.Description,
		"role":        string(opts.Role),
		"config":      string(opts.Config),
	}
	if opts.MatchRules != nil {
		args["match_rules"] = opts.MatchRules
	}
	result, err := a.callTool(ctx, "device_template_create", args)
	if err != nil {
		return nil, err
	}

	var template entities.DeviceTemplate
	configAsBytes := func(obj map[string]interface{}) {
		if config, ok := obj["config"].(string); ok {
			obj["config"] = base64.StdEncoding.EncodeToString([]byte(config))
		}
	}
	if err := decodeToolEntity("CreateTemplate", result, &template, configAsBytes); err != nil {
		return nil, err
	}
	return &CreateTemplateResult{Template: &template}, nil
}

// GetTemplate retrieves a template by ID via MCP.
func (a *MCPAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "GetTemplate"}
}

// UpdateTemplate updates an existing template via MCP.
func (a *MCPAdapter) UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "UpdateTemplate"}
}

// DeleteTemplate removes a template via MCP.
func (a *MCPAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "DeleteTemplate"}
}

// ListTemplates lists all templates via MCP.
func (a *MCPAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "ListTemplates"}
}

// CreateProfileFromTemplate creates a profile from a template via MCP.
//
// The profile inherits the template's tenant: the tool's overrides cannot
// move a profile to another tenant, so opts.TenantID is not sent.
func (a *MCPAdapter) CreateProfileFromTemplate(ctx context.Context, opts CreateProfileFromTemplateOptions) (*CreateProfileResult, error) {
	overrides := map[string]interface{}{
		"name":        opts.Name,
		"ek_serial":   opts.EKSerial,
		"mac_address": opts.MACAddress,
	}
	result, err := a.callTool(ctx, "profile_create_from_template", map[string]interface{}{
		"template_id": opts.TemplateID,
		"overrides":   overrides,
	})
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := decodeToolEntity("CreateProfileFromTemplate", result, &profile, nil); err != nil {
		return nil, err
	}
	return &CreateProfileResult{Profile: &profile}, nil
}

// decodeToolEntity decodes a device tool result into entity; fixup, when
// set, adjusts any field the tool renders differently from the entity.
func decodeToolEntity(operation string, result json.RawMessage, entity any, fixup func(map[string]interface{})) error {
	if err := decodeDomainEntity(result, entity, fixup); err != nil {
		return &MCPAdapterError{Operation: operation, Message: "failed to parse response: " + err.Error()}
	}
	return nil
}

// decodeDomainEntity decodes a device entity in the domain JSON shape the
// REST handlers and MCP tools return. Both send a uint64 id as a decimal
// string, which the entity's numeric id cannot take, so the id becomes a
// JSON number first.
func decodeDomainEntity(data []byte, entity any, fixup func(map[string]interface{})) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var obj map[string]interface{}
	if err := decoder.Decode(&obj); err != nil {
		return err
	}
	if id, ok := obj["id"].(string); ok {
		obj["id"] = json.Number(id)
	}
	if fixup != nil {
		fixup(obj)
	}

	normalized, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return json.Unmarshal(normalized, entity)
}

// FindConfigForDevice finds the config for a device via MCP.
func (a *MCPAdapter) FindConfigForDevice(ctx context.Context, opts FindConfigForDeviceOptions) (*FindConfigForDeviceResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "FindConfigForDevice"}
}

// AssignProfileToDevice assigns a profile to a device via MCP.
//
// The options struct is passed as the tool arguments unchanged, matching every
// other method here: profile_id is declared as an integer in the tool schema
// but the server's getInt64 parses a JSON string too, so the adapter's string
// IDs reach it correctly.
func (a *MCPAdapter) AssignProfileToDevice(ctx context.Context, opts AssignProfileToDeviceOptions) (*AssignProfileToDeviceResult, error) {
	result, err := a.callTool(ctx, "profile_assign_to_device", opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(result, &profile); err != nil {
		return nil, &MCPAdapterError{
			Operation: "AssignProfileToDevice",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &AssignProfileToDeviceResult{Profile: &profile}, nil
}

// DisableDevice calls the device_disable tool.
func (a *MCPAdapter) DisableDevice(ctx context.Context, opts DisableDeviceOptions) (*DeviceLifecycleResult, error) {
	return a.deviceLifecycle(ctx, "DisableDevice", "device_disable", map[string]interface{}{
		"device_id": opts.DeviceID,
		"reason":    opts.Reason,
	})
}

// EnableDevice calls the device_enable tool.
func (a *MCPAdapter) EnableDevice(ctx context.Context, opts EnableDeviceOptions) (*DeviceLifecycleResult, error) {
	return a.deviceLifecycle(ctx, "EnableDevice", "device_enable", map[string]interface{}{
		"device_id": opts.DeviceID,
	})
}

// deviceLifecycle calls a lifecycle tool, whose result is the
// platform.v1 DeviceLifecycleResponse marshalled as JSON.
func (a *MCPAdapter) deviceLifecycle(ctx context.Context, op, tool string, args map[string]interface{}) (*DeviceLifecycleResult, error) {
	result, err := a.callTool(ctx, tool, args)
	if err != nil {
		return nil, err
	}

	var resp pb.DeviceLifecycleResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: op,
			Message:   "failed to parse response: " + err.Error(),
		}
	}
	return lifecycleResultFromProto(&resp), nil
}

// Verify MCPAdapter implements DeviceCommands
var _ DeviceCommands = (*MCPAdapter)(nil)
