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

// CreateProfile creates a new device profile through profile_create.
func (a *MCPAdapter) CreateProfile(ctx context.Context, opts CreateProfileOptions) (*CreateProfileResult, error) {
	args := profileToolArgs(opts.Name, opts.Model, opts.Role, opts.MACPrefix, opts.SerialPrefix, opts.MatchRules)
	profile, err := a.callProfileTool(ctx, "CreateProfile", "profile_create", args)
	if err != nil {
		return nil, err
	}
	return &CreateProfileResult{Profile: profile}, nil
}

// GetProfile retrieves a profile by ID through profile_get_by_id.
func (a *MCPAdapter) GetProfile(ctx context.Context, opts GetProfileOptions) (*GetProfileResult, error) {
	args := map[string]interface{}{"id": opts.ProfileID}
	profile, err := a.callProfileTool(ctx, "GetProfile", "profile_get_by_id", args)
	if err != nil {
		return nil, err
	}
	return &GetProfileResult{Profile: profile}, nil
}

// UpdateProfile updates an existing profile through profile_update_by_id.
func (a *MCPAdapter) UpdateProfile(ctx context.Context, opts UpdateProfileOptions) (*UpdateProfileResult, error) {
	args := profileToolArgs(opts.Name, opts.Model, opts.Role, opts.MACPrefix, opts.SerialPrefix, opts.MatchRules)
	args["id"] = opts.ProfileID
	profile, err := a.callProfileTool(ctx, "UpdateProfile", "profile_update_by_id", args)
	if err != nil {
		return nil, err
	}
	return &UpdateProfileResult{Profile: profile}, nil
}

// DeleteProfile removes a profile through profile_delete_by_id.
func (a *MCPAdapter) DeleteProfile(ctx context.Context, opts DeleteProfileOptions) (*DeleteProfileResult, error) {
	_, err := a.callTool(ctx, "profile_delete_by_id", map[string]interface{}{"id": opts.ProfileID})
	if err != nil {
		return nil, err
	}

	return &DeleteProfileResult{Success: true}, nil
}

// ListProfiles lists profiles through profile_list_all, which pages by
// page and page_size; Limit is the page size and Offset selects the page.
func (a *MCPAdapter) ListProfiles(ctx context.Context, opts ListProfilesOptions) (*ListProfilesResult, error) {
	args := map[string]interface{}{}
	if opts.Limit > 0 {
		args["page_size"] = opts.Limit
		args["page"] = opts.Offset/opts.Limit + 1
	}
	result, err := a.callTool(ctx, "profile_list_all", args)
	if err != nil {
		return nil, err
	}

	var page struct {
		Profiles []json.RawMessage `json:"profiles"`
		Total    int               `json:"total"`
	}
	if err := json.Unmarshal(result, &page); err != nil {
		return nil, &MCPAdapterError{
			Operation: "ListProfiles",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	listResult := &ListProfilesResult{
		Profiles: make([]*entities.DeviceProfile, 0, len(page.Profiles)),
		Total:    page.Total,
	}
	for _, raw := range page.Profiles {
		var profile entities.DeviceProfile
		if err := decodeToolEntity("ListProfiles", raw, &profile, nil); err != nil {
			return nil, err
		}
		listResult.Profiles = append(listResult.Profiles, &profile)
	}
	return listResult, nil
}

// ============================================================================
// Profile Lookups
// ============================================================================

// FindProfileByMACAddress finds the profile whose MAC prefix fits the
// address, through profile_find_by_mac.
func (a *MCPAdapter) FindProfileByMACAddress(ctx context.Context, opts FindProfileByMACAddressOptions) (*FindProfileByMACAddressResult, error) {
	args := map[string]interface{}{"mac_address": opts.MACAddress}
	profile, err := a.callProfileTool(ctx, "FindProfileByMACAddress", "profile_find_by_mac", args)
	if err != nil {
		return nil, err
	}
	return &FindProfileByMACAddressResult{Profile: profile}, nil
}

// FindProfileBySerial finds the profile whose serial prefix fits the
// serial, through profile_find_by_serial.
func (a *MCPAdapter) FindProfileBySerial(ctx context.Context, opts FindProfileBySerialOptions) (*FindProfileBySerialResult, error) {
	args := map[string]interface{}{"serial": opts.Serial}
	profile, err := a.callProfileTool(ctx, "FindProfileBySerial", "profile_find_by_serial", args)
	if err != nil {
		return nil, err
	}
	return &FindProfileBySerialResult{Profile: profile}, nil
}

// FindMatchingProfile finds a profile matching device attributes through
// profile_find_matching.
func (a *MCPAdapter) FindMatchingProfile(ctx context.Context, opts FindMatchingProfileOptions) (*FindMatchingProfileResult, error) {
	args := map[string]interface{}{
		"mac_address": opts.MACAddress,
		"serial":      opts.Serial,
		"model":       opts.Model,
	}
	profile, err := a.callProfileTool(ctx, "FindMatchingProfile", "profile_find_matching", args)
	if err != nil {
		return nil, err
	}
	return &FindMatchingProfileResult{Profile: profile}, nil
}

// callProfileTool runs a profile tool whose reply is one profile.
func (a *MCPAdapter) callProfileTool(ctx context.Context, operation, tool string, args map[string]interface{}) (*entities.DeviceProfile, error) {
	result, err := a.callTool(ctx, tool, args)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := decodeToolEntity(operation, result, &profile, nil); err != nil {
		return nil, err
	}
	return &profile, nil
}

// profileToolArgs builds the profile_create / profile_update_by_id
// arguments. The tools take match rules only as a match_rules object, so the
// options' top-level prefixes are folded into one, as the gRPC adapter does;
// explicit MatchRules win.
func profileToolArgs(name, model string, role entities.DeviceRole, macPrefix, serialPrefix string, rules *entities.ProfileMatchRules) map[string]interface{} {
	args := map[string]interface{}{
		"name":  name,
		"model": model,
		"role":  string(role),
	}
	if rules == nil && (macPrefix != "" || serialPrefix != "") {
		rules = &entities.ProfileMatchRules{MACPrefix: macPrefix, SerialPrefix: serialPrefix}
	}
	if rules != nil {
		args["match_rules"] = rules
	}
	return args
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
	args := templateToolArgs(opts.TenantID, opts.Name, opts.Description, opts.Role, opts.Config, opts.MatchRules)
	result, err := a.callTool(ctx, "device_template_create", args)
	if err != nil {
		return nil, err
	}

	var template entities.DeviceTemplate
	if err := decodeToolEntity("CreateTemplate", result, &template, templateConfigAsBytes); err != nil {
		return nil, err
	}
	return &CreateTemplateResult{Template: &template}, nil
}

// GetTemplate retrieves a template by ID via MCP.
func (a *MCPAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	result, err := a.callTool(ctx, "device_template_get", map[string]interface{}{"id": opts.TemplateID})
	if err != nil {
		return nil, err
	}

	var template entities.DeviceTemplate
	if err := decodeToolEntity("GetTemplate", result, &template, templateConfigAsBytes); err != nil {
		return nil, err
	}
	return &GetTemplateResult{Template: &template}, nil
}

// UpdateTemplate replaces a stored template via device_template_update,
// which takes the device_template_create arguments plus the id.
func (a *MCPAdapter) UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error) {
	args := templateToolArgs(opts.TenantID, opts.Name, opts.Description, opts.Role, opts.Config, opts.MatchRules)
	args["id"] = opts.TemplateID
	result, err := a.callTool(ctx, "device_template_update", args)
	if err != nil {
		return nil, err
	}

	var template entities.DeviceTemplate
	if err := decodeToolEntity("UpdateTemplate", result, &template, templateConfigAsBytes); err != nil {
		return nil, err
	}
	return &UpdateTemplateResult{Template: &template}, nil
}

// DeleteTemplate removes a template via device_template_delete, which
// answers {"success": true, "id": "<id>"}.
func (a *MCPAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	result, err := a.callTool(ctx, "device_template_delete", map[string]interface{}{"id": opts.TemplateID})
	if err != nil {
		return nil, err
	}

	var deleted struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(result, &deleted); err != nil {
		return nil, &MCPAdapterError{Operation: "DeleteTemplate", Message: "failed to parse response: " + err.Error()}
	}
	return &DeleteTemplateResult{Success: deleted.Success}, nil
}

// ListTemplates pages templates via device_template_list, which pages by
// page and page_size; Limit is the page size and Offset selects the page.
// The tool has no role argument, so a role filter is refused.
func (a *MCPAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	if opts.Role != "" {
		return nil, ErrNoListFilter{Transport: "MCP", Operation: "ListTemplates", Filter: "role"}
	}
	args := map[string]interface{}{}
	if opts.Limit > 0 {
		args["page_size"] = opts.Limit
		args["page"] = opts.Offset/opts.Limit + 1
	}
	result, err := a.callTool(ctx, "device_template_list", args)
	if err != nil {
		return nil, err
	}

	var page struct {
		Templates []json.RawMessage `json:"templates"`
		Total     int               `json:"total"`
	}
	if err := json.Unmarshal(result, &page); err != nil {
		return nil, &MCPAdapterError{Operation: "ListTemplates", Message: "failed to parse response: " + err.Error()}
	}

	listResult := &ListTemplatesResult{
		Templates: make([]*entities.DeviceTemplate, 0, len(page.Templates)),
		Total:     page.Total,
	}
	for _, raw := range page.Templates {
		var template entities.DeviceTemplate
		if err := decodeToolEntity("ListTemplates", raw, &template, templateConfigAsBytes); err != nil {
			return nil, err
		}
		listResult.Templates = append(listResult.Templates, &template)
	}
	return listResult, nil
}

// templateToolArgs builds the device_template_create arguments, which
// device_template_update shares. config travels as YAML text.
func templateToolArgs(tenantID, name, description string, role entities.DeviceRole, config []byte, rules *entities.ProfileMatchRules) map[string]interface{} {
	args := map[string]interface{}{
		"tenant_id":   tenantID,
		"name":        name,
		"description": description,
		"role":        string(role),
		"config":      string(config),
	}
	if rules != nil {
		args["match_rules"] = rules
	}
	return args
}

// templateConfigAsBytes turns a template result's config text into the
// base64 form the entity's []byte Config decodes from.
func templateConfigAsBytes(obj map[string]interface{}) {
	if config, ok := obj["config"].(string); ok {
		obj["config"] = base64.StdEncoding.EncodeToString([]byte(config))
	}
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
	args := map[string]interface{}{}
	if opts.EKSerial != "" {
		args["ek_serial"] = opts.EKSerial
	}
	if opts.MACAddress != "" {
		args["mac_address"] = opts.MACAddress
	}
	profile, err := a.callProfileTool(ctx, "FindConfigForDevice", "profile_find_config", args)
	if err != nil {
		return nil, err
	}
	return &FindConfigForDeviceResult{Profile: profile}, nil
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
