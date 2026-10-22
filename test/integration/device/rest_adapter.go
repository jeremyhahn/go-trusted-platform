//go:build integration

package device

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	wsdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// RESTAdapterError represents an error from the REST adapter
type RESTAdapterError struct {
	Operation  string
	StatusCode int
	Message    string
	Body       string
}

func (e *RESTAdapterError) Error() string {
	return fmt.Sprintf("REST adapter error [%s]: %s (status: %d, body: %s)",
		e.Operation, e.Message, e.StatusCode, e.Body)
}

// RESTAdapter implements DeviceCommands using REST API
type RESTAdapter struct {
	endpoint string
	client   *http.Client
}

// NewRESTAdapter creates a new REST adapter
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{
		endpoint: GetRESTEndpoint(),
		client:   helpers.NewAdminHTTPClient(0),
	}
}

// Setup prepares the adapter for testing
func (a *RESTAdapter) Setup(ctx context.Context) error {
	// Verify endpoint is reachable
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/health", nil)
	if err != nil {
		return &RESTAdapterError{
			Operation: "Setup",
			Message:   "failed to create request: " + err.Error(),
		}
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return &RESTAdapterError{
			Operation: "Setup",
			Message:   "endpoint not reachable: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	return nil
}

// Teardown cleans up after testing
func (a *RESTAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name
func (a *RESTAdapter) Name() string {
	return "REST"
}

// doRequest performs an HTTP request and returns the response body
func (a *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, &RESTAdapterError{
				Operation: method + " " + path,
				Message:   "failed to marshal request: " + err.Error(),
			}
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, a.endpoint+path, reqBody)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: method + " " + path,
			Message:   "failed to create request: " + err.Error(),
		}
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: method + " " + path,
			Message:   "request failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "failed to read response: " + err.Error(),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &RESTAdapterError{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "request failed",
			Body:       string(respBody),
		}
	}

	return unwrapPayload(method+" "+path, respBody)
}

// unwrapPayload returns the resource a device route answered with: the
// payload of the webservice envelope (pkg/webservice/v1/response), or the
// daemon's bare object. An empty body yields no payload.
func unwrapPayload(operation string, body []byte) ([]byte, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	// Two listeners serve the device routes (docs/device/api.md §2.2): the
	// webservice wraps every answer in {code, success, payload}, while the
	// daemon REST listener the integration platformd runs answers with the
	// bare object. Only an object carrying a payload key is unwrapped.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, &RESTAdapterError{
			Operation: operation,
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}
	if payload, ok := fields["payload"]; ok {
		return payload, nil
	}
	return body, nil
}

// decodePayload decodes an unwrapped payload into out.
func decodePayload(operation string, payload []byte, out any) error {
	if err := json.Unmarshal(payload, out); err != nil {
		return &RESTAdapterError{
			Operation: operation,
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(payload),
		}
	}
	return nil
}

// ErrRESTNoFilter reports a list filter the server's route has no query
// parameter for. Sending it anyway would return an unfiltered page that
// looks like a filtered one, so the adapter refuses it.
type ErrRESTNoFilter struct {
	Operation string
	Filter    string
}

func (e ErrRESTNoFilter) Error() string {
	return fmt.Sprintf("REST route for %s has no %s query parameter", e.Operation, e.Filter)
}

// pageQuery maps the suite's limit/offset window onto the server's 1-based
// page/page_size query parameters. A zero limit keeps the server defaults.
func pageQuery(limit, offset int) string {
	if limit <= 0 {
		return ""
	}
	query := url.Values{}
	query.Set("page", strconv.Itoa(offset/limit+1))
	query.Set("page_size", strconv.Itoa(limit))
	return "?" + query.Encode()
}

// decodeDevice decodes the daemon's DeviceResponse payload.
func decodeDevice(operation string, payload []byte) (*entities.Device, error) {
	var device deviceJSON
	if err := decodePayload(operation, payload, &device); err != nil {
		return nil, err
	}
	return device.entity(), nil
}

// decodeProfile decodes the daemon's ProfileFullResponse payload.
func decodeProfile(operation string, payload []byte) (*entities.DeviceProfile, error) {
	var profile wsdevice.ProfileFullResponse
	if err := decodePayload(operation, payload, &profile); err != nil {
		return nil, err
	}
	return profileEntity(&profile), nil
}

// decodeTemplate decodes the daemon's TemplateResponse payload.
func decodeTemplate(operation string, payload []byte) (*entities.DeviceTemplate, error) {
	var template wsdevice.TemplateResponse
	if err := decodePayload(operation, payload, &template); err != nil {
		return nil, err
	}
	return templateEntity(&template), nil
}

// profileEntity maps the daemon's ProfileFullResponse onto the entity the
// suite asserts on. The response carries no tenant or BMC block, and its PCR
// baseline is a read-only hex rendering the suite never compares, so those
// entity fields stay zero.
func profileEntity(p *wsdevice.ProfileFullResponse) *entities.DeviceProfile {
	profile := &entities.DeviceProfile{
		ID:                    p.ID.Uint64(),
		Name:                  p.Name,
		Model:                 p.Model,
		Role:                  entities.DeviceRole(p.Role),
		EventLog:              p.EventLog,
		Zone:                  p.Zone,
		EnrollmentNetwork:     p.EnrollmentNetwork,
		PostEnrollmentNetwork: p.PostEnrollmentNetwork,
		FailureNetwork:        p.FailureNetwork,
		MatchRules:            (*entities.ProfileMatchRules)(p.MatchRules),
		TLSServerName:         p.TLSServerName,
		Config:                p.Config,
		EKSerial:              p.EKSerial,
		EKCert:                p.EKCert,
		MACAddress:            p.MACAddress,
		Assigned:              p.Assigned,
		AssignedAt:            p.AssignedAt,
	}
	if p.PlatformdConfig != nil {
		profile.PlatformdConfig = &entities.PlatformdConfigRef{
			ConfigType: p.PlatformdConfig.ConfigType,
			Reference:  p.PlatformdConfig.Reference,
			ConfigName: p.PlatformdConfig.ConfigName,
			ConfigPath: p.PlatformdConfig.ConfigPath,
			Version:    p.PlatformdConfig.Version,
		}
	}
	if len(p.Networks) > 0 {
		profile.Networks = make(map[string]*entities.NetworkPhaseConfig, len(p.Networks))
		for name, phase := range p.Networks {
			profile.Networks[name] = networkPhaseEntity(phase)
		}
	}
	return profile
}

// networkPhaseEntity maps one network phase of a ProfileFullResponse.
func networkPhaseEntity(phase *wsdevice.NetworkPhaseResponse) *entities.NetworkPhaseConfig {
	if phase == nil {
		return nil
	}
	config := &entities.NetworkPhaseConfig{
		VLAN:       phase.VLAN,
		DHCPPool:   (*entities.DHCPPoolConfig)(phase.DHCPPool),
		StaticIP:   phase.StaticIP,
		Gateway:    phase.Gateway,
		DNS:        phase.DNS,
		AuthMethod: entities.AuthMethod(phase.AuthMethod),
		Zone:       phase.Zone,
		Subnet:     phase.Subnet,
		DNSServers: phase.DNSServers,
		DHCP:       phase.DHCP,
	}
	for _, acl := range phase.ACLs {
		config.ACLs = append(config.ACLs, entities.ACLConfig(acl))
	}
	return config
}

// templateEntity maps the daemon's TemplateResponse onto the entity the
// suite asserts on. The response carries no BMC block.
func templateEntity(t *wsdevice.TemplateResponse) *entities.DeviceTemplate {
	return &entities.DeviceTemplate{
		ID:          t.ID.Uint64(),
		TenantID:    t.TenantID,
		Name:        t.Name,
		Description: t.Description,
		Role:        entities.DeviceRole(t.Role),
		Config:      t.Config,
		MatchRules:  (*entities.ProfileMatchRules)(t.MatchRules),
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}
}

// decodeEnvelopedEntity unwraps the standard {code, success, payload}
// envelope the device handlers answer with and decodes the payload, a
// domain entity with a string id, into entity.
// ============================================================================
// Device CRUD Operations
// ============================================================================

// RegisterDevice registers a new device
func (a *RESTAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	path := "/api/v1/devices"

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	device, err := decodeDevice("RegisterDevice", body)
	if err != nil {
		return nil, err
	}
	return &RegisterDeviceResult{Device: device}, nil
}

// GetDevice retrieves a device by its key
func (a *RESTAdapter) GetDevice(ctx context.Context, opts GetDeviceOptions) (*GetDeviceResult, error) {
	path := fmt.Sprintf("/api/v1/devices/%s", opts.DeviceID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	device, err := decodeDevice("GetDevice", body)
	if err != nil {
		return nil, err
	}
	return &GetDeviceResult{Device: device}, nil
}

// UpdateDevice updates an existing device
func (a *RESTAdapter) UpdateDevice(ctx context.Context, opts UpdateDeviceOptions) (*UpdateDeviceResult, error) {
	path := fmt.Sprintf("/api/v1/devices/%s", opts.DeviceID)

	body, err := a.doRequest(ctx, http.MethodPut, path, opts)
	if err != nil {
		return nil, err
	}

	device, err := decodeDevice("UpdateDevice", body)
	if err != nil {
		return nil, err
	}
	return &UpdateDeviceResult{Device: device}, nil
}

// DeleteDevice removes a device
func (a *RESTAdapter) DeleteDevice(ctx context.Context, opts DeleteDeviceOptions) (*DeleteDeviceResult, error) {
	path := fmt.Sprintf("/api/v1/devices/%s", opts.DeviceID)

	_, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &DeleteDeviceResult{Success: true}, nil
}

// ListDevices lists all devices with optional filtering
func (a *RESTAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	if opts.ProfileID != "" || opts.Status != "" {
		return nil, ErrRESTNoFilter{Operation: "ListDevices", Filter: "profile or status"}
	}

	body, err := a.doRequest(ctx, http.MethodGet, "/api/v1/devices"+pageQuery(opts.Limit, opts.Offset), nil)
	if err != nil {
		return nil, err
	}

	var page struct {
		Devices    []deviceJSON                `json:"devices"`
		Pagination wsdevice.PaginationResponse `json:"pagination"`
	}
	if err := decodePayload("ListDevices", body, &page); err != nil {
		return nil, err
	}

	result := &ListDevicesResult{
		Devices: make([]*entities.Device, 0, len(page.Devices)),
		Total:   page.Pagination.Total,
	}
	for _, d := range page.Devices {
		result.Devices = append(result.Devices, d.entity())
	}
	return result, nil
}

// ============================================================================
// Device Lookups
// ============================================================================

// FindBySerial finds a device by its serial number
func (a *RESTAdapter) FindBySerial(ctx context.Context, opts FindBySerialOptions) (*FindBySerialResult, error) {
	path := fmt.Sprintf("/api/v1/devices/serial/%s", opts.Serial)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	device, err := decodeDevice("FindBySerial", body)
	if err != nil {
		return nil, err
	}
	return &FindBySerialResult{Device: device}, nil
}

// ============================================================================
// Profile CRUD Operations
// ============================================================================

// CreateProfile creates a new device profile
func (a *RESTAdapter) CreateProfile(ctx context.Context, opts CreateProfileOptions) (*CreateProfileResult, error) {
	path := "/api/v1/devices/profiles"

	// The REST ProfileRequest carries the prefixes inside match_rules, as
	// the MCP profile tools do (docs/device/api-reference-rest.md).
	reqBody := profileToolArgs(opts.Name, opts.Model, opts.Role, opts.MACPrefix, opts.SerialPrefix, opts.MatchRules)
	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	profile, err := decodeProfile("CreateProfile", body)
	if err != nil {
		return nil, err
	}
	return &CreateProfileResult{Profile: profile}, nil
}

// GetProfile retrieves a profile by its key
func (a *RESTAdapter) GetProfile(ctx context.Context, opts GetProfileOptions) (*GetProfileResult, error) {
	path := fmt.Sprintf("/api/v1/devices/profiles/%s", opts.ProfileID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	profile, err := decodeProfile("GetProfile", body)
	if err != nil {
		return nil, err
	}
	return &GetProfileResult{Profile: profile}, nil
}

// UpdateProfile updates an existing profile
func (a *RESTAdapter) UpdateProfile(ctx context.Context, opts UpdateProfileOptions) (*UpdateProfileResult, error) {
	path := fmt.Sprintf("/api/v1/devices/profiles/%s", opts.ProfileID)

	reqBody := profileToolArgs(opts.Name, opts.Model, opts.Role, opts.MACPrefix, opts.SerialPrefix, opts.MatchRules)
	body, err := a.doRequest(ctx, http.MethodPut, path, reqBody)
	if err != nil {
		return nil, err
	}

	profile, err := decodeProfile("UpdateProfile", body)
	if err != nil {
		return nil, err
	}
	return &UpdateProfileResult{Profile: profile}, nil
}

// DeleteProfile removes a profile
func (a *RESTAdapter) DeleteProfile(ctx context.Context, opts DeleteProfileOptions) (*DeleteProfileResult, error) {
	path := fmt.Sprintf("/api/v1/devices/profiles/%s", opts.ProfileID)

	_, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &DeleteProfileResult{Success: true}, nil
}

// ListProfiles lists all profiles with optional filtering
func (a *RESTAdapter) ListProfiles(ctx context.Context, opts ListProfilesOptions) (*ListProfilesResult, error) {
	if opts.Role != "" {
		return nil, ErrRESTNoFilter{Operation: "ListProfiles", Filter: "role"}
	}

	body, err := a.doRequest(ctx, http.MethodGet, "/api/v1/devices/profiles"+pageQuery(opts.Limit, opts.Offset), nil)
	if err != nil {
		return nil, err
	}

	var page wsdevice.ProfileListResponse
	if err := decodePayload("ListProfiles", body, &page); err != nil {
		return nil, err
	}

	result := &ListProfilesResult{
		Profiles: make([]*entities.DeviceProfile, 0, len(page.Profiles)),
		Total:    page.Pagination.Total,
	}
	for i := range page.Profiles {
		result.Profiles = append(result.Profiles, profileEntity(&page.Profiles[i]))
	}
	return result, nil
}

// ============================================================================
// Profile Lookups
// ============================================================================

// FindProfileByMACAddress finds a profile by MAC address prefix
func (a *RESTAdapter) FindProfileByMACAddress(ctx context.Context, opts FindProfileByMACAddressOptions) (*FindProfileByMACAddressResult, error) {
	path := fmt.Sprintf("/api/v1/device/profiles/mac/%s", opts.MACAddress)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	profile, err := decodeProfile("FindProfileByMACAddress", body)
	if err != nil {
		return nil, err
	}
	return &FindProfileByMACAddressResult{Profile: profile}, nil
}

// FindProfileBySerial finds a profile by serial pattern
func (a *RESTAdapter) FindProfileBySerial(ctx context.Context, opts FindProfileBySerialOptions) (*FindProfileBySerialResult, error) {
	path := fmt.Sprintf("/api/v1/device/profiles/serial/%s", opts.Serial)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	profile, err := decodeProfile("FindProfileBySerial", body)
	if err != nil {
		return nil, err
	}
	return &FindProfileBySerialResult{Profile: profile}, nil
}

// FindMatchingProfile finds a profile matching device attributes
func (a *RESTAdapter) FindMatchingProfile(ctx context.Context, opts FindMatchingProfileOptions) (*FindMatchingProfileResult, error) {
	path := "/api/v1/device/profiles/match"

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	profile, err := decodeProfile("FindMatchingProfile", body)
	if err != nil {
		return nil, err
	}
	return &FindMatchingProfileResult{Profile: profile}, nil
}

// ============================================================================
// Attestation
// ============================================================================

// RecordAttestCert records the device's attestation certificate via the
// live admin route POST /api/v1/devices/{id}/attest-cert/record.
func (a *RESTAdapter) RecordAttestCert(ctx context.Context, opts RecordAttestCertOptions) (*RecordAttestCertResult, error) {
	path := fmt.Sprintf("/api/v1/devices/%s/attest-cert/record", opts.DeviceID)

	body, err := a.doRequest(ctx, http.MethodPost, path, map[string]bool{
		"reissue":          opts.Reissue,
		"clear_on_refusal": opts.ClearOnRefusal,
	})
	if err != nil {
		return nil, err
	}

	var result RecordAttestCertResult
	if err := decodePayload("RecordAttestCert", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AttestDevice submits quote evidence to the device attestation route and
// returns the platform's verdict. The route is /api/v1/devices/{id}/attest,
// which is where the daemon actually serves it; the tenant-scoped path this
// adapter used before existed on no router, so every call 404'd and the
// suite's skip guard swallowed it (#403).
func (a *RESTAdapter) AttestDevice(ctx context.Context, opts AttestDeviceOptions) (*AttestDeviceResult, error) {
	path := fmt.Sprintf("/api/v1/devices/%s/attest", opts.DeviceID)

	body, err := a.doRequest(ctx, http.MethodPost, path, map[string][]byte{"evidence": opts.Evidence})
	if err != nil {
		return nil, err
	}

	var result AttestDeviceResult
	if err := decodePayload("AttestDevice", body, &result); err != nil {
		return nil, err
	}
	if result.DeviceID == "" {
		result.DeviceID = opts.DeviceID
	}

	return &result, nil
}

// ============================================================================
// Template CRUD Operations
// ============================================================================

// CreateTemplate creates a new device template
func (a *RESTAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	path := "/api/v1/device/templates"

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	template, err := decodeTemplate("CreateTemplate", body)
	if err != nil {
		return nil, err
	}
	return &CreateTemplateResult{Template: template}, nil
}

// GetTemplate retrieves a template by ID
func (a *RESTAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	path := fmt.Sprintf("/api/v1/device/templates/%s", opts.TemplateID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	template, err := decodeTemplate("GetTemplate", body)
	if err != nil {
		return nil, err
	}
	return &GetTemplateResult{Template: template}, nil
}

// UpdateTemplate updates an existing template
func (a *RESTAdapter) UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error) {
	path := fmt.Sprintf("/api/v1/device/templates/%s", opts.TemplateID)

	body, err := a.doRequest(ctx, http.MethodPut, path, opts)
	if err != nil {
		return nil, err
	}

	template, err := decodeTemplate("UpdateTemplate", body)
	if err != nil {
		return nil, err
	}
	return &UpdateTemplateResult{Template: template}, nil
}

// DeleteTemplate removes a template
func (a *RESTAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	path := fmt.Sprintf("/api/v1/device/templates/%s", opts.TemplateID)

	_, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &DeleteTemplateResult{Success: true}, nil
}

// ListTemplates lists all templates
func (a *RESTAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	if opts.Role != "" {
		return nil, ErrRESTNoFilter{Operation: "ListTemplates", Filter: "role"}
	}

	body, err := a.doRequest(ctx, http.MethodGet, "/api/v1/device/templates"+pageQuery(opts.Limit, opts.Offset), nil)
	if err != nil {
		return nil, err
	}

	var page wsdevice.TemplateListResponse
	if err := decodePayload("ListTemplates", body, &page); err != nil {
		return nil, err
	}

	result := &ListTemplatesResult{
		Templates: make([]*entities.DeviceTemplate, 0, len(page.Templates)),
		Total:     page.Pagination.Total,
	}
	for i := range page.Templates {
		result.Templates = append(result.Templates, templateEntity(&page.Templates[i]))
	}
	return result, nil
}

// ============================================================================
// Template Operations
// ============================================================================

// CreateProfileFromTemplate creates a profile from a template
func (a *RESTAdapter) CreateProfileFromTemplate(ctx context.Context, opts CreateProfileFromTemplateOptions) (*CreateProfileResult, error) {
	// The template id travels in the path; the profile inherits the
	// template's tenant, so only the overrides go in the body.
	path := fmt.Sprintf("/api/v1/device/templates/%s/create-profile", opts.TemplateID)
	overrides := map[string]string{}
	for key, value := range map[string]string{
		"name":        opts.Name,
		"ek_serial":   opts.EKSerial,
		"mac_address": opts.MACAddress,
	} {
		if value != "" {
			overrides[key] = value
		}
	}

	body, err := a.doRequest(ctx, http.MethodPost, path, map[string]interface{}{"overrides": overrides})
	if err != nil {
		return nil, err
	}

	profile, err := decodeProfile("CreateProfileFromTemplate", body)
	if err != nil {
		return nil, err
	}
	return &CreateProfileResult{Profile: profile}, nil
}

// FindConfigForDevice finds the config for a device by EK serial or MAC
func (a *RESTAdapter) FindConfigForDevice(ctx context.Context, opts FindConfigForDeviceOptions) (*FindConfigForDeviceResult, error) {
	path := "/api/v1/device/profiles/find-config"

	// Build query parameters
	params := ""
	if opts.EKSerial != "" {
		params += fmt.Sprintf("&ek_serial=%s", opts.EKSerial)
	}
	if opts.MACAddress != "" {
		params += fmt.Sprintf("&mac=%s", opts.MACAddress)
	}
	if params != "" {
		path += "?" + params[1:] // Remove leading &
	}

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	profile, err := decodeProfile("FindConfigForDevice", body)
	if err != nil {
		return nil, err
	}
	return &FindConfigForDeviceResult{Profile: profile}, nil
}

// AssignProfileToDevice assigns a profile to a device identity
func (a *RESTAdapter) AssignProfileToDevice(ctx context.Context, opts AssignProfileToDeviceOptions) (*AssignProfileToDeviceResult, error) {
	path := fmt.Sprintf("/api/v1/device/profiles/%s/assign", opts.ProfileID)

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	profile, err := decodeProfile("AssignProfileToDevice", body)
	if err != nil {
		return nil, err
	}
	return &AssignProfileToDeviceResult{Profile: profile}, nil
}

// restLifecycleEnvelope is the success envelope around a disable or enable
// answer; the handler sends the uint64 device id as a string.
type restLifecycleEnvelope struct {
	Payload struct {
		DeviceID               string `json:"device_id"`
		State                  string `json:"state"`
		PreviousState          string `json:"previous_state"`
		StateReason            string `json:"state_reason"`
		ReattestationRequested bool   `json:"reattestation_requested"`
	} `json:"payload"`
}

// DisableDevice sends POST /api/v1/devices/{id}/disable.
func (a *RESTAdapter) DisableDevice(ctx context.Context, opts DisableDeviceOptions) (*DeviceLifecycleResult, error) {
	path := fmt.Sprintf("/api/v1/devices/%s/disable", opts.DeviceID)
	return a.deviceLifecycle(ctx, "DisableDevice", path, map[string]string{"reason": opts.Reason})
}

// EnableDevice sends POST /api/v1/devices/{id}/enable.
func (a *RESTAdapter) EnableDevice(ctx context.Context, opts EnableDeviceOptions) (*DeviceLifecycleResult, error) {
	path := fmt.Sprintf("/api/v1/devices/%s/enable", opts.DeviceID)
	return a.deviceLifecycle(ctx, "EnableDevice", path, nil)
}

func (a *RESTAdapter) deviceLifecycle(ctx context.Context, op, path string, reqBody interface{}) (*DeviceLifecycleResult, error) {
	body, err := a.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var envelope restLifecycleEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, &RESTAdapterError{
			Operation: op,
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}
	p := envelope.Payload
	return &DeviceLifecycleResult{
		DeviceID:               p.DeviceID,
		State:                  p.State,
		PreviousState:          p.PreviousState,
		StateReason:            p.StateReason,
		ReattestationRequested: p.ReattestationRequested,
	}, nil
}

// Verify RESTAdapter implements DeviceCommands
var _ DeviceCommands = (*RESTAdapter)(nil)
