//go:build integration

package device

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
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
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: helpers.TLSConfigOrInsecure(),
			},
		},
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

	return respBody, nil
}

// ============================================================================
// Device CRUD Operations
// ============================================================================

// RegisterDevice registers a new device
func (a *RESTAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/devices", opts.TenantID)

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(body, &device); err != nil {
		return nil, &RESTAdapterError{
			Operation: "RegisterDevice",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &RegisterDeviceResult{Device: &device}, nil
}

// GetDevice retrieves a device by its key
func (a *RESTAdapter) GetDevice(ctx context.Context, opts GetDeviceOptions) (*GetDeviceResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/devices/%s", opts.TenantID, opts.DeviceID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(body, &device); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetDevice",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &GetDeviceResult{Device: &device}, nil
}

// UpdateDevice updates an existing device
func (a *RESTAdapter) UpdateDevice(ctx context.Context, opts UpdateDeviceOptions) (*UpdateDeviceResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/devices/%s", opts.TenantID, opts.DeviceID)

	body, err := a.doRequest(ctx, http.MethodPut, path, opts)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(body, &device); err != nil {
		return nil, &RESTAdapterError{
			Operation: "UpdateDevice",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &UpdateDeviceResult{Device: &device}, nil
}

// DeleteDevice removes a device
func (a *RESTAdapter) DeleteDevice(ctx context.Context, opts DeleteDeviceOptions) (*DeleteDeviceResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/devices/%s", opts.TenantID, opts.DeviceID)

	_, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &DeleteDeviceResult{Success: true}, nil
}

// ListDevices lists all devices with optional filtering
func (a *RESTAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/devices", opts.TenantID)

	// Build query parameters
	params := ""
	if opts.ProfileID != "" {
		params += fmt.Sprintf("&profile_id=%s", opts.ProfileID)
	}
	if opts.Status != "" {
		params += fmt.Sprintf("&status=%s", opts.Status)
	}
	if opts.Limit > 0 {
		params += fmt.Sprintf("&limit=%d", opts.Limit)
	}
	if opts.Offset > 0 {
		params += fmt.Sprintf("&offset=%d", opts.Offset)
	}
	if params != "" {
		path += "?" + params[1:] // Remove leading &
	}

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result ListDevicesResult
	if err := json.Unmarshal(body, &result); err != nil {
		// Try parsing as array
		var devices []*entities.Device
		if err := json.Unmarshal(body, &devices); err != nil {
			return nil, &RESTAdapterError{
				Operation: "ListDevices",
				Message:   "failed to parse response: " + err.Error(),
				Body:      string(body),
			}
		}
		result.Devices = devices
		result.Total = len(devices)
	}

	return &result, nil
}

// ============================================================================
// Device Lookups
// ============================================================================

// FindBySerial finds a device by its serial number
func (a *RESTAdapter) FindBySerial(ctx context.Context, opts FindBySerialOptions) (*FindBySerialResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/devices/by-serial/%s", opts.TenantID, opts.Serial)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(body, &device); err != nil {
		return nil, &RESTAdapterError{
			Operation: "FindBySerial",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &FindBySerialResult{Device: &device}, nil
}

// ============================================================================
// Profile CRUD Operations
// ============================================================================

// CreateProfile creates a new device profile
func (a *RESTAdapter) CreateProfile(ctx context.Context, opts CreateProfileOptions) (*CreateProfileResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-profiles", opts.TenantID)

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &RESTAdapterError{
			Operation: "CreateProfile",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &CreateProfileResult{Profile: &profile}, nil
}

// GetProfile retrieves a profile by its key
func (a *RESTAdapter) GetProfile(ctx context.Context, opts GetProfileOptions) (*GetProfileResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-profiles/%s", opts.TenantID, opts.ProfileID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetProfile",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &GetProfileResult{Profile: &profile}, nil
}

// UpdateProfile updates an existing profile
func (a *RESTAdapter) UpdateProfile(ctx context.Context, opts UpdateProfileOptions) (*UpdateProfileResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-profiles/%s", opts.TenantID, opts.ProfileID)

	body, err := a.doRequest(ctx, http.MethodPut, path, opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &RESTAdapterError{
			Operation: "UpdateProfile",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &UpdateProfileResult{Profile: &profile}, nil
}

// DeleteProfile removes a profile
func (a *RESTAdapter) DeleteProfile(ctx context.Context, opts DeleteProfileOptions) (*DeleteProfileResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-profiles/%s", opts.TenantID, opts.ProfileID)

	_, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &DeleteProfileResult{Success: true}, nil
}

// ListProfiles lists all profiles with optional filtering
func (a *RESTAdapter) ListProfiles(ctx context.Context, opts ListProfilesOptions) (*ListProfilesResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-profiles", opts.TenantID)

	// Build query parameters
	params := ""
	if opts.Role != "" {
		params += fmt.Sprintf("&role=%s", opts.Role)
	}
	if opts.Limit > 0 {
		params += fmt.Sprintf("&limit=%d", opts.Limit)
	}
	if opts.Offset > 0 {
		params += fmt.Sprintf("&offset=%d", opts.Offset)
	}
	if params != "" {
		path += "?" + params[1:] // Remove leading &
	}

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result ListProfilesResult
	if err := json.Unmarshal(body, &result); err != nil {
		// Try parsing as array
		var profiles []*entities.DeviceProfile
		if err := json.Unmarshal(body, &profiles); err != nil {
			return nil, &RESTAdapterError{
				Operation: "ListProfiles",
				Message:   "failed to parse response: " + err.Error(),
				Body:      string(body),
			}
		}
		result.Profiles = profiles
		result.Total = len(profiles)
	}

	return &result, nil
}

// ============================================================================
// Profile Lookups
// ============================================================================

// FindProfileByMACAddress finds a profile by MAC address prefix
func (a *RESTAdapter) FindProfileByMACAddress(ctx context.Context, opts FindProfileByMACAddressOptions) (*FindProfileByMACAddressResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-profiles/by-mac/%s", opts.TenantID, opts.MACAddress)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &RESTAdapterError{
			Operation: "FindProfileByMACAddress",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &FindProfileByMACAddressResult{Profile: &profile}, nil
}

// FindProfileBySerial finds a profile by serial pattern
func (a *RESTAdapter) FindProfileBySerial(ctx context.Context, opts FindProfileBySerialOptions) (*FindProfileBySerialResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-profiles/by-serial/%s", opts.TenantID, opts.Serial)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &RESTAdapterError{
			Operation: "FindProfileBySerial",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &FindProfileBySerialResult{Profile: &profile}, nil
}

// FindMatchingProfile finds a profile matching device attributes
func (a *RESTAdapter) FindMatchingProfile(ctx context.Context, opts FindMatchingProfileOptions) (*FindMatchingProfileResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-profiles/match", opts.TenantID)

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &RESTAdapterError{
			Operation: "FindMatchingProfile",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &FindMatchingProfileResult{Profile: &profile}, nil
}

// ============================================================================
// Attestation
// ============================================================================

// RecordAttestCert records the device's attestation certificate via the
// live admin route POST /api/v1/devices/{id}/attest-cert/record.
func (a *RESTAdapter) RecordAttestCert(ctx context.Context, opts RecordAttestCertOptions) (*RecordAttestCertResult, error) {
	path := fmt.Sprintf("/api/v1/devices/%s/attest-cert/record", opts.DeviceID)

	body, err := a.doRequest(ctx, http.MethodPost, path, map[string]bool{"reissue": opts.Reissue})
	if err != nil {
		return nil, err
	}

	var result RecordAttestCertResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "RecordAttestCert",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
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
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "AttestDevice",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
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
	path := fmt.Sprintf("/api/v1/tenants/%s/device-templates", opts.TenantID)

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var template entities.DeviceTemplate
	if err := json.Unmarshal(body, &template); err != nil {
		return nil, &RESTAdapterError{
			Operation: "CreateTemplate",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &CreateTemplateResult{Template: &template}, nil
}

// GetTemplate retrieves a template by ID
func (a *RESTAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-templates/%s", opts.TenantID, opts.TemplateID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var template entities.DeviceTemplate
	if err := json.Unmarshal(body, &template); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetTemplate",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &GetTemplateResult{Template: &template}, nil
}

// UpdateTemplate updates an existing template
func (a *RESTAdapter) UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-templates/%s", opts.TenantID, opts.TemplateID)

	body, err := a.doRequest(ctx, http.MethodPut, path, opts)
	if err != nil {
		return nil, err
	}

	var template entities.DeviceTemplate
	if err := json.Unmarshal(body, &template); err != nil {
		return nil, &RESTAdapterError{
			Operation: "UpdateTemplate",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &UpdateTemplateResult{Template: &template}, nil
}

// DeleteTemplate removes a template
func (a *RESTAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-templates/%s", opts.TenantID, opts.TemplateID)

	_, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &DeleteTemplateResult{Success: true}, nil
}

// ListTemplates lists all templates
func (a *RESTAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-templates", opts.TenantID)

	// Build query parameters
	params := ""
	if opts.Role != "" {
		params += fmt.Sprintf("&role=%s", opts.Role)
	}
	if opts.Limit > 0 {
		params += fmt.Sprintf("&limit=%d", opts.Limit)
	}
	if opts.Offset > 0 {
		params += fmt.Sprintf("&offset=%d", opts.Offset)
	}
	if params != "" {
		path += "?" + params[1:] // Remove leading &
	}

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result ListTemplatesResult
	if err := json.Unmarshal(body, &result); err != nil {
		// Try parsing as array
		var templates []*entities.DeviceTemplate
		if err := json.Unmarshal(body, &templates); err != nil {
			return nil, &RESTAdapterError{
				Operation: "ListTemplates",
				Message:   "failed to parse response: " + err.Error(),
				Body:      string(body),
			}
		}
		result.Templates = templates
		result.Total = len(templates)
	}

	return &result, nil
}

// ============================================================================
// Template Operations
// ============================================================================

// CreateProfileFromTemplate creates a profile from a template
func (a *RESTAdapter) CreateProfileFromTemplate(ctx context.Context, opts CreateProfileFromTemplateOptions) (*CreateProfileResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-templates/%s/create-profile", opts.TenantID, opts.TemplateID)

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &RESTAdapterError{
			Operation: "CreateProfileFromTemplate",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &CreateProfileResult{Profile: &profile}, nil
}

// FindConfigForDevice finds the config for a device by EK serial or MAC
func (a *RESTAdapter) FindConfigForDevice(ctx context.Context, opts FindConfigForDeviceOptions) (*FindConfigForDeviceResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-profiles/find-config", opts.TenantID)

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

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &RESTAdapterError{
			Operation: "FindConfigForDevice",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &FindConfigForDeviceResult{Profile: &profile}, nil
}

// AssignProfileToDevice assigns a profile to a device identity
func (a *RESTAdapter) AssignProfileToDevice(ctx context.Context, opts AssignProfileToDeviceOptions) (*AssignProfileToDeviceResult, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/device-profiles/%s/assign", opts.TenantID, opts.ProfileID)

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &RESTAdapterError{
			Operation: "AssignProfileToDevice",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &AssignProfileToDeviceResult{Profile: &profile}, nil
}

// Verify RESTAdapter implements DeviceCommands
var _ DeviceCommands = (*RESTAdapter)(nil)
