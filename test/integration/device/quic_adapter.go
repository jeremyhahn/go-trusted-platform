//go:build integration

package device

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

// QUICAdapterError represents an error from the QUIC adapter
type QUICAdapterError struct {
	Operation string
	Message   string
}

func (e *QUICAdapterError) Error() string {
	return fmt.Sprintf("QUIC adapter error [%s]: %s", e.Operation, e.Message)
}

// ErrQUICNotImplemented indicates a method is not yet implemented for QUIC.
type ErrQUICNotImplemented struct {
	Method string
}

func (e ErrQUICNotImplemented) Error() string {
	return fmt.Sprintf("QUIC method %s not implemented", e.Method)
}

// QUICRequest represents a QUIC protocol request
type QUICRequest struct {
	Method string      `json:"method"`
	Path   string      `json:"path"`
	Body   interface{} `json:"body,omitempty"`
}

// QUICResponse represents a QUIC protocol response
type QUICResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	Error  string          `json:"error,omitempty"`
}

// QUICAdapter implements DeviceCommands using QUIC protocol
type QUICAdapter struct {
	endpoint   string
	conn       *quicgo.Conn
	tlsConfig  *tls.Config
	quicConfig *quicgo.Config
}

// NewQUICAdapter creates a new QUIC adapter
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		endpoint:  GetQUICEndpoint(),
		tlsConfig: helpers.QUICTLSConfig([]string{"device-quic"}),
		quicConfig: &quicgo.Config{
			EnableDatagrams: true,
		},
	}
}

// Setup prepares the adapter for testing
func (a *QUICAdapter) Setup(ctx context.Context) error {
	conn, err := quicgo.DialAddr(ctx, a.endpoint, a.tlsConfig, a.quicConfig)
	if err != nil {
		return &QUICAdapterError{
			Operation: "Setup",
			Message:   "failed to connect: " + err.Error(),
		}
	}

	a.conn = conn
	return nil
}

// Teardown cleans up after testing
func (a *QUICAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.CloseWithError(0, "teardown")
	}
	return nil
}

// Name returns the adapter name
func (a *QUICAdapter) Name() string {
	return "QUIC"
}

// doRequest performs a QUIC request and returns the response
func (a *QUICAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	stream, err := a.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   "failed to open stream: " + err.Error(),
		}
	}
	defer stream.Close()

	// Send request
	req := QUICRequest{
		Method: method,
		Path:   path,
		Body:   body,
	}

	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   "failed to marshal request: " + err.Error(),
		}
	}

	if _, err := stream.Write(reqData); err != nil {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   "failed to write request: " + err.Error(),
		}
	}

	// Close write side to signal end of request
	if err := stream.Close(); err != nil {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   "failed to close write: " + err.Error(),
		}
	}

	// Read response
	respData, err := io.ReadAll(stream)
	if err != nil {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   "failed to read response: " + err.Error(),
		}
	}

	var resp QUICResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   "failed to unmarshal response: " + err.Error(),
		}
	}

	if resp.Error != "" {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   resp.Error,
		}
	}

	return resp.Body, nil
}

// ============================================================================
// Device CRUD Operations
// ============================================================================

// RegisterDevice registers a new device
func (a *QUICAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	path := fmt.Sprintf("/tenants/%s/devices", opts.TenantID)

	body, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(body, &device); err != nil {
		return nil, &QUICAdapterError{
			Operation: "RegisterDevice",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &RegisterDeviceResult{Device: &device}, nil
}

// GetDevice retrieves a device by its key
func (a *QUICAdapter) GetDevice(ctx context.Context, opts GetDeviceOptions) (*GetDeviceResult, error) {
	path := fmt.Sprintf("/tenants/%s/devices/%s", opts.TenantID, opts.DeviceID)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(body, &device); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GetDevice",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &GetDeviceResult{Device: &device}, nil
}

// UpdateDevice updates an existing device
func (a *QUICAdapter) UpdateDevice(ctx context.Context, opts UpdateDeviceOptions) (*UpdateDeviceResult, error) {
	path := fmt.Sprintf("/tenants/%s/devices/%s", opts.TenantID, opts.DeviceID)

	body, err := a.doRequest(ctx, "PUT", path, opts)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(body, &device); err != nil {
		return nil, &QUICAdapterError{
			Operation: "UpdateDevice",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &UpdateDeviceResult{Device: &device}, nil
}

// DeleteDevice removes a device
func (a *QUICAdapter) DeleteDevice(ctx context.Context, opts DeleteDeviceOptions) (*DeleteDeviceResult, error) {
	path := fmt.Sprintf("/tenants/%s/devices/%s", opts.TenantID, opts.DeviceID)

	_, err := a.doRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return nil, err
	}

	return &DeleteDeviceResult{Success: true}, nil
}

// ListDevices lists all devices with optional filtering
func (a *QUICAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	path := fmt.Sprintf("/tenants/%s/devices", opts.TenantID)

	body, err := a.doRequest(ctx, "GET", path, opts)
	if err != nil {
		return nil, err
	}

	var result ListDevicesResult
	if err := json.Unmarshal(body, &result); err != nil {
		var devices []*entities.Device
		if err := json.Unmarshal(body, &devices); err != nil {
			return nil, &QUICAdapterError{
				Operation: "ListDevices",
				Message:   "failed to parse response: " + err.Error(),
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
func (a *QUICAdapter) FindBySerial(ctx context.Context, opts FindBySerialOptions) (*FindBySerialResult, error) {
	path := fmt.Sprintf("/tenants/%s/devices/by-serial/%s", opts.TenantID, opts.Serial)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(body, &device); err != nil {
		return nil, &QUICAdapterError{
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
func (a *QUICAdapter) CreateProfile(ctx context.Context, opts CreateProfileOptions) (*CreateProfileResult, error) {
	path := fmt.Sprintf("/tenants/%s/device-profiles", opts.TenantID)

	body, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &QUICAdapterError{
			Operation: "CreateProfile",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &CreateProfileResult{Profile: &profile}, nil
}

// GetProfile retrieves a profile by its key
func (a *QUICAdapter) GetProfile(ctx context.Context, opts GetProfileOptions) (*GetProfileResult, error) {
	path := fmt.Sprintf("/tenants/%s/device-profiles/%s", opts.TenantID, opts.ProfileID)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GetProfile",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &GetProfileResult{Profile: &profile}, nil
}

// UpdateProfile updates an existing profile
func (a *QUICAdapter) UpdateProfile(ctx context.Context, opts UpdateProfileOptions) (*UpdateProfileResult, error) {
	path := fmt.Sprintf("/tenants/%s/device-profiles/%s", opts.TenantID, opts.ProfileID)

	body, err := a.doRequest(ctx, "PUT", path, opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &QUICAdapterError{
			Operation: "UpdateProfile",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &UpdateProfileResult{Profile: &profile}, nil
}

// DeleteProfile removes a profile
func (a *QUICAdapter) DeleteProfile(ctx context.Context, opts DeleteProfileOptions) (*DeleteProfileResult, error) {
	path := fmt.Sprintf("/tenants/%s/device-profiles/%s", opts.TenantID, opts.ProfileID)

	_, err := a.doRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return nil, err
	}

	return &DeleteProfileResult{Success: true}, nil
}

// ListProfiles lists all profiles with optional filtering
func (a *QUICAdapter) ListProfiles(ctx context.Context, opts ListProfilesOptions) (*ListProfilesResult, error) {
	path := fmt.Sprintf("/tenants/%s/device-profiles", opts.TenantID)

	body, err := a.doRequest(ctx, "GET", path, opts)
	if err != nil {
		return nil, err
	}

	var result ListProfilesResult
	if err := json.Unmarshal(body, &result); err != nil {
		var profiles []*entities.DeviceProfile
		if err := json.Unmarshal(body, &profiles); err != nil {
			return nil, &QUICAdapterError{
				Operation: "ListProfiles",
				Message:   "failed to parse response: " + err.Error(),
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
func (a *QUICAdapter) FindProfileByMACAddress(ctx context.Context, opts FindProfileByMACAddressOptions) (*FindProfileByMACAddressResult, error) {
	path := fmt.Sprintf("/tenants/%s/device-profiles/by-mac/%s", opts.TenantID, opts.MACAddress)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &QUICAdapterError{
			Operation: "FindProfileByMACAddress",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &FindProfileByMACAddressResult{Profile: &profile}, nil
}

// FindProfileBySerial finds a profile by serial pattern
func (a *QUICAdapter) FindProfileBySerial(ctx context.Context, opts FindProfileBySerialOptions) (*FindProfileBySerialResult, error) {
	path := fmt.Sprintf("/tenants/%s/device-profiles/by-serial/%s", opts.TenantID, opts.Serial)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &QUICAdapterError{
			Operation: "FindProfileBySerial",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &FindProfileBySerialResult{Profile: &profile}, nil
}

// FindMatchingProfile finds a profile matching device attributes
func (a *QUICAdapter) FindMatchingProfile(ctx context.Context, opts FindMatchingProfileOptions) (*FindMatchingProfileResult, error) {
	path := fmt.Sprintf("/tenants/%s/device-profiles/match", opts.TenantID)

	body, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, &QUICAdapterError{
			Operation: "FindMatchingProfile",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &FindMatchingProfileResult{Profile: &profile}, nil
}

// ============================================================================
// Attestation
// ============================================================================

// RecordAttestCert records the device's attestation certificate.
func (a *QUICAdapter) RecordAttestCert(ctx context.Context, opts RecordAttestCertOptions) (*RecordAttestCertResult, error) {
	path := fmt.Sprintf("/devices/%s/attest-cert/record", opts.DeviceID)

	body, err := a.doRequest(ctx, "POST", path, map[string]bool{"reissue": opts.Reissue})
	if err != nil {
		return nil, err
	}

	var result RecordAttestCertResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "RecordAttestCert",
			Message:   "failed to parse response: " + err.Error(),
		}
	}
	return &result, nil
}

// AttestDevice performs device attestation
func (a *QUICAdapter) AttestDevice(ctx context.Context, opts AttestDeviceOptions) (*AttestDeviceResult, error) {
	path := fmt.Sprintf("/tenants/%s/devices/%s/attest", opts.TenantID, opts.DeviceID)

	body, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return nil, err
	}

	var result AttestDeviceResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "AttestDevice",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// ============================================================================
// Template CRUD Operations (not yet available via QUIC)
// ============================================================================

// CreateTemplate creates a new device template via QUIC.
func (a *QUICAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	return nil, ErrQUICNotImplemented{Method: "CreateTemplate"}
}

// GetTemplate retrieves a template by ID via QUIC.
func (a *QUICAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	return nil, ErrQUICNotImplemented{Method: "GetTemplate"}
}

// UpdateTemplate updates an existing template via QUIC.
func (a *QUICAdapter) UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error) {
	return nil, ErrQUICNotImplemented{Method: "UpdateTemplate"}
}

// DeleteTemplate removes a template via QUIC.
func (a *QUICAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	return nil, ErrQUICNotImplemented{Method: "DeleteTemplate"}
}

// ListTemplates lists all templates via QUIC.
func (a *QUICAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	return nil, ErrQUICNotImplemented{Method: "ListTemplates"}
}

// CreateProfileFromTemplate creates a profile from a template via QUIC.
func (a *QUICAdapter) CreateProfileFromTemplate(ctx context.Context, opts CreateProfileFromTemplateOptions) (*CreateProfileResult, error) {
	return nil, ErrQUICNotImplemented{Method: "CreateProfileFromTemplate"}
}

// FindConfigForDevice finds the config for a device via QUIC.
func (a *QUICAdapter) FindConfigForDevice(ctx context.Context, opts FindConfigForDeviceOptions) (*FindConfigForDeviceResult, error) {
	return nil, ErrQUICNotImplemented{Method: "FindConfigForDevice"}
}

// AssignProfileToDevice assigns a profile to a device via QUIC.
func (a *QUICAdapter) AssignProfileToDevice(ctx context.Context, opts AssignProfileToDeviceOptions) (*AssignProfileToDeviceResult, error) {
	return nil, ErrQUICNotImplemented{Method: "AssignProfileToDevice"}
}

// Verify QUICAdapter implements DeviceCommands
var _ DeviceCommands = (*QUICAdapter)(nil)
